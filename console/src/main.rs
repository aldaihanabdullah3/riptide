/// C2 Operator Console — interactive TUI for managing implants.
///
/// Usage:
///   console --server http://127.0.0.1:8080
///   console --server https://10.0.0.1:8443 --no-tls-verify
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use std::io;

mod api;
mod app;
mod ui;

#[derive(Parser)]
#[command(name = "console", about = "C2 Operator Console")]
struct Cli {
    /// C2 server URL
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,

    /// Skip TLS certificate verification
    #[arg(long)]
    no_tls_verify: bool,

    /// Non-interactive mode (for scripting)
    #[arg(long)]
    no_tui: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();

    if cli.no_tui {
        // Non-interactive mode: just print sessions
        let client = api::C2Client::new(&cli.server, cli.no_tls_verify);
        match client.list_sessions().await {
            Ok(resp) => {
                println!("Sessions ({}):", resp.count);
                for s in &resp.sessions {
                    let last_seen = chrono::DateTime::parse_from_rfc3339(&s.last_seen)
                        .unwrap_or_else(|_| chrono::DateTime::UNIX_EPOCH.into());
                    let now: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
                    let ago = now.signed_duration_since(last_seen).num_seconds();
                    println!(
                        "  {} | {} | {} | {} | {} | {}s ago",
                        s.implant_id, s.hostname, s.tier, s.privileges, s.status, ago,
                    );
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
        return Ok(());
    }

    // Interactive TUI mode
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let client = api::C2Client::new(&cli.server, cli.no_tls_verify);
    let mut app = app::App::new(client);

    let result = run_tui(&mut terminal, &mut app).await;

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_tui<B: Backend>(terminal: &mut Terminal<B>, app: &mut app::App) -> io::Result<()> {
    // Initial session fetch
    app.refresh_sessions().await;

    loop {
        terminal.draw(|f| ui::render(f, app))?;

        // Poll for events with a 500ms timeout
        if event::poll(std::time::Duration::from_millis(500))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => {
                            if app.input_mode == app::InputMode::Normal {
                                app.running = false;
                                break;
                            } else {
                                app.input_buffer.push('q');
                            }
                        }
                        KeyCode::Esc => {
                            if app.input_mode == app::InputMode::Editing {
                                app.input_mode = app::InputMode::Normal;
                                app.input_buffer.clear();
                            } else if app.selected_session.is_some() {
                                app.selected_session = None;
                                app.interact_history.clear();
                            }
                        }
                        KeyCode::Enter => {
                            if app.input_mode == app::InputMode::Editing {
                                let cmd = app.input_buffer.clone();
                                app.input_buffer.clear();
                                app.input_mode = app::InputMode::Normal;
                                app.execute_command(&cmd).await;
                            } else if app.selected_session.is_none() {
                                // Select highlighted session
                                if let Some(s) = app.sessions.get(app.session_list_idx) {
                                    let (id, hostname, ip, os, tier, uid, status) = (
                                        s.implant_id.clone(),
                                        s.hostname.clone(),
                                        s.ip.clone(),
                                        s.os.clone(),
                                        s.tier.clone(),
                                        s.uid,
                                        s.status.clone(),
                                    );
                                    app.selected_session = Some(id.clone());
                                    app.interact_history.clear();
                                    app.input_mode = app::InputMode::Editing;
                                    app.add_interact(&format!("Selected session: {} ({})", hostname, id));
                                    app.add_interact(&format!(
                                        "  IP: {} | OS: {} | Tier: {} | UID: {} | Status: {}",
                                        ip, os, tier, uid, status
                                    ));
                                }
                            }
                        }
                        KeyCode::Char('i') => {
                            if app.selected_session.is_some() && app.input_mode == app::InputMode::Normal {
                                app.input_mode = app::InputMode::Editing;
                                app.input_buffer.clear();
                            }
                        }
                        KeyCode::Char('r') => {
                            if app.input_mode == app::InputMode::Normal {
                                app.refresh_sessions().await;
                            } else {
                                app.input_buffer.push('r');
                            }
                        }
                        KeyCode::Up => {
                            if app.input_mode == app::InputMode::Normal {
                                if app.selected_session.is_some() {
                                    app.scroll_offset = app.scroll_offset.saturating_sub(1);
                                } else {
                                    app.session_list_idx = app.session_list_idx.saturating_sub(1);
                                }
                            } else {
                                app.input_buffer.push_str("\x1b[A");
                            }
                        }
                        KeyCode::Down => {
                            if app.input_mode == app::InputMode::Normal {
                                if app.selected_session.is_some() {
                                    app.scroll_offset += 1;
                                } else {
                                    let max = app.sessions.len().saturating_sub(1);
                                    if app.session_list_idx < max {
                                        app.session_list_idx += 1;
                                    }
                                }
                            } else {
                                app.input_buffer.push_str("\x1b[B");
                            }
                        }
                        KeyCode::Backspace => {
                            if app.input_mode == app::InputMode::Editing {
                                app.input_buffer.pop();
                            }
                        }
                        KeyCode::Char(c) => {
                            if app.input_mode == app::InputMode::Editing {
                                app.input_buffer.push(c);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Auto-refresh sessions every 5 seconds
        if app.refresh_timer.elapsed().as_secs() >= 5 {
            app.refresh_sessions().await;
        }
    }

    Ok(())
}
