/// TUI rendering for the operator console.
use crate::app::{App, InputMode, LogLevel};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

pub fn render(frame: &mut Frame, app: &App) {
    let size = frame.size();
    let area = Rect::new(0, 0, size.width, size.height);

    // Main layout: sidebar | main area
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    // Left sidebar: sessions + events
    render_sidebar(frame, app, main_chunks[0]);

    // Right: interact area
    if app.selected_session.is_some() {
        render_interact_area(frame, app, main_chunks[1]);
    } else {
        render_welcome_area(frame, app, main_chunks[1]);
    }
}

fn render_sidebar(frame: &mut Frame, app: &App, area: Rect) {
    let sidebar_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_session_list(frame, app, sidebar_chunks[0]);
    render_event_log(frame, app, sidebar_chunks[1]);
}

fn render_session_list(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .sessions
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let prefix = if i == app.session_list_idx { "▶ " } else { "  " };
            let icon = match s.status.as_str() {
                "active" => "●",
                "idle" => "○",
                "stale" => "◌",
                _ => "✕",
            };
            let color = match s.status.as_str() {
                "active" => Color::Green,
                "idle" => Color::Yellow,
                "stale" => Color::DarkGray,
                _ => Color::Red,
            };

            // Parse last_seen safely
            let ago = parse_last_seen(&s.last_seen);

            let line = format!(
                "{}{} {} | {} | {} | {}",
                prefix, icon, s.hostname, s.tier, s.privileges, ago
            );
            ListItem::new(line).style(Style::default().fg(color))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(" Sessions ({}) ", app.sessions.len()))
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));

    frame.render_widget(list, area);
}

fn parse_last_seen(s: &str) -> String {
    let parsed = chrono::DateTime::parse_from_rfc3339(s).unwrap_or_else(|_| {
        chrono::DateTime::UNIX_EPOCH.into()
    });
    let now: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
    let secs = now.signed_duration_since(parsed).num_seconds();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

fn render_event_log(frame: &mut Frame, app: &App, area: Rect) {
    let lines: Vec<Line> = app
        .event_log
        .iter()
        .rev()
        .take(20)
        .map(|entry| {
            let color = match entry.level {
                LogLevel::Info => Color::Gray,
                LogLevel::Success => Color::Green,
                LogLevel::Warn => Color::Yellow,
                LogLevel::Error => Color::Red,
            };
            let ts = entry.timestamp.format("%H:%M:%S").to_string();
            Line::from(vec![
                Span::styled(format!("[{}] ", ts), Style::default().fg(Color::DarkGray)),
                Span::styled(&entry.message, Style::default().fg(color)),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(Text::from(lines))
        .block(Block::default().title(" Events ").borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

fn render_welcome_area(frame: &mut Frame, app: &App, area: Rect) {
    let status_msg = &app.status_message;
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  C2 Operator Console",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Use ↑/↓ to navigate sessions, 'i' for command mode",
            Style::default().fg(Color::Gray),
        )),
        Line::from(Span::styled(
            "  Press 'r' to refresh sessions, 'q' to quit",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Quick Reference:",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled("    sessions     - Refresh session list", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("    use <id>     - Select session", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("    shell <cmd>  - Execute shell command", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("    recon        - Network reconnaissance", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("    creds        - Credential harvesting", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("    privesc      - Privilege escalation", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("    exfil <path> - Exfiltrate files", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("    download <p> - Download file", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("    help         - Show all commands", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("    q            - Quit", Style::default().fg(Color::Gray))),
        Line::from(""),
    ];

    if let Some(s) = app.sessions.get(app.session_list_idx) {
        lines.push(Line::from(Span::styled(
            format!("  Highlighted: {} ({}) | {} | {}", s.hostname, s.tier, s.privileges, s.ip),
            Style::default().fg(Color::White),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  {}", status_msg),
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(Text::from(lines))
        .block(Block::default().title(" Welcome ").borders(Borders::ALL));

    frame.render_widget(paragraph, area);
}

fn render_interact_area(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(area);

    // Session info header
    let session_id = app.selected_session.as_ref().unwrap();
    let session_info = app.sessions.iter().find(|s| &s.implant_id == session_id);

    // Output area
    let output_lines: Vec<Line> = app
        .interact_history
        .iter()
        .rev()
        .take(100)
        .rev()
        .map(|line| Line::from(Span::styled(line, Style::default().fg(Color::White))))
        .collect();

    let title = if let Some(s) = session_info {
        format!(" [{}] {} ({}) ", s.tier, s.hostname, s.implant_id)
    } else {
        format!(" Session: {} ", session_id)
    };

    let output = Paragraph::new(Text::from(output_lines))
        .block(Block::default().title(title).borders(Borders::ALL))
        .scroll((app.scroll_offset as u16, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(output, chunks[0]);

    // Input bar
    let input_text = match app.input_mode {
        InputMode::Normal => {
            if app.selected_session.is_some() {
                String::from("Press 'i' to enter command mode | 'q' quit | 'Esc' deselect")
            } else {
                String::from("Press 'i' to enter command mode | 'q' quit")
            }
        }
        InputMode::Editing => {
            format!("> {}", app.input_buffer)
        }
    };

    let input_style = match app.input_mode {
        InputMode::Editing => Style::default().fg(Color::Yellow),
        InputMode::Normal => Style::default().fg(Color::DarkGray),
    };

    let input = Paragraph::new(input_text)
        .block(Block::default().borders(Borders::ALL).border_style(input_style))
        .style(input_style);

    frame.render_widget(input, chunks[1]);
}

#[allow(dead_code)]
pub fn cursor_position(app: &App) -> Option<(u16, u16)> {
    if app.input_mode == InputMode::Editing {
        Some(((app.input_buffer.len() + 2) as u16, 0))
    } else {
        None
    }
}
