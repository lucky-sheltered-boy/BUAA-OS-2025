#include <fs.h>
#include <lib.h>

#define debug 0

static int file_close(struct Fd *fd);
static int file_read(struct Fd *fd, void *buf, u_int n, u_int offset);
static int file_write(struct Fd *fd, const void *buf, u_int n, u_int offset);
static int file_stat(struct Fd *fd, struct Stat *stat);

// Dot represents choosing the member within the struct declaration
// to initialize, with no need to consider the order of members.
struct Dev devfile = {
    .dev_id = 'f',
    .dev_name = "file",
    .dev_read = file_read,
    .dev_write = file_write,
    .dev_close = file_close,
    .dev_stat = file_stat,
};

// Overview:
//  Open a file (or directory).
//
// Returns:
//  the file descriptor on success,
//  the underlying error on failure.
int open(const char *path, int mode) {
	int r;

	// Step 1: Alloc a new 'Fd' using 'fd_alloc' in fd.c.
	// Hint: return the error code if failed.
	struct Fd *fd;
	/* Exercise 5.9: Your code here. (1/5) */
	r = fd_alloc(&fd);
	if (r) {
		return r;
	}

	// Step 2: Prepare the 'fd' using 'fsipc_open' in fsipc.c.
	/* Exercise 5.9: Your code here. (2/5) */
	char cwd[1024] = {0};
	syscall_get_cwd(cwd);
	char finalpath[1024] = {0};
	_get_final_path(cwd, path, finalpath);


	r = fsipc_open(finalpath, mode, fd);
	if (r) {
		return r;
	}

	// Step 3: Set 'va' to the address of the page where the 'fd''s data is cached, using
	// 'fd2data'. Set 'size' and 'fileid' correctly with the value in 'fd' as a 'Filefd'.
	char *va;
	struct Filefd *ffd;
	u_int size, fileid;
	/* Exercise 5.9: Your code here. (3/5) */
	va = fd2data(fd);
	ffd = (struct Filefd *)fd;
	size = ffd->f_file.f_size;
	fileid = ffd->f_fileid;

	// Step 4: Map the file content using 'fsipc_map'.
	for (int i = 0; i < size; i += PTMAP) {
		/* Exercise 5.9: Your code here. (4/5) */
		r = fsipc_map(fileid, i, va + i);
		if (r) {
			return r;
		}
	}

	// Step 5: Return the number of file descriptor using 'fd2num'.
	/* Exercise 5.9: Your code here. (5/5) */
	return fd2num(fd);
}

int _get_final_path(const char *cwd, const char *path, char *finalpath) {
    if (!cwd || !path || !finalpath) {
        return -E_INVAL; // Invalid arguments
    }

    char constructed_path[MAXPATHLEN * 2]; // Intermediate buffer for path construction

    // 1. Determine if 'path' is absolute or relative and construct initial full path
    if (path[0] == '/') { // Absolute path
        if (_mystrlen(path) >= 1024) {
            // printf("Error: Absolute path too long.\n"); // Optional debug
            return -1; // Path too long
        }
        _mystrcpy(constructed_path, path);
        // As per your spec: "绝对路径，此时将这个绝对路径复制到第三个参数finalpath即可，返回0"
        // This means no stat check for absolute paths here.
        // Normalization is still good practice.
        if (_normalize_path(constructed_path) < 0) {
             // printf("Error: Failed to normalize absolute path '%s'\n", path);
        }
        _mystrcpy(finalpath, constructed_path);
        return 0; // Success for absolute path as per spec (no immediate stat)

    } else { // Relative path
        // Construct full path: cwd + "/" + path
        if (_mystrlen(cwd) + 1 + _mystrlen(path) + 1 > sizeof(constructed_path)) { // +1 for potential slash, +1 for null
            // printf("Error: Constructed relative path too long.\n");
            return -1;
        }
        _mystrcpy(constructed_path, cwd);
        // Add slash if cwd is not "/" and path is not empty
        if (_mystrcmp(cwd, "/") != 0 && constructed_path[_mystrlen(constructed_path) - 1] != '/') {
            _mystrcat(constructed_path, "/");
        } else if (_mystrcmp(cwd, "/") == 0 && _mystrlen(constructed_path) > 1) { 
            // If cwd was "/" and something got appended making it "//path", fix to "/path"
            // This case is usually handled by normalize_path later.
            // More simply, if cwd is "/", just don't add another slash if path is not empty.
        }
        _mystrcat(constructed_path, path);

        // Normalize the constructed path (handles ".", "..", "//")
        if (_normalize_path(constructed_path) < 0) {
            // printf("Error: Failed to normalize constructed path '%s'\n", temp_path);
        }
        

        // Path exists and is a directory
        _mystrcpy(finalpath, constructed_path);
        return 0; // Success
    }
}

int _normalize_path(char *path_buf) {
    if (path_buf == NULL) return -1;

    char components[128][128]; 
    int comp_idx = 0;
    const char *p = path_buf;
    int is_absolute = (*p == '/');

    // Phase 1: Parse into components, handling "." and ".."
    if (is_absolute) {
        p++; 
        while (*p == '/') p++; 
    }

    while (*p) {
        char current_comp_val[MAXNAMELEN];
        char *c_ptr = current_comp_val;
        while (*p != '/' && *p != '\0') {
            if (c_ptr - current_comp_val < MAXNAMELEN - 1) *c_ptr++ = *p;
            p++;
        }
        *c_ptr = '\0';

        if (_mystrcmp(current_comp_val, "..") == 0) {
            if (comp_idx > 0 && _mystrcmp(components[comp_idx - 1], "..") != 0) {
                comp_idx--; // Pop if last wasn't ".."
            } else if (!is_absolute) { // Relative path: push ".." or if stack top is ".." push another
                if (comp_idx < 128) _mystrncpy(components[comp_idx++], "..", MAXNAMELEN-1);
                else return -E_BAD_PATH; // Path too complex/long
            }
            // If absolute and comp_idx is 0 (or was ".."), ".." from root is ignored or handled by pop
        } else if (_mystrcmp(current_comp_val, ".") != 0 && current_comp_val[0] != '\0') {
            if (comp_idx < 128) _mystrncpy(components[comp_idx++], current_comp_val, MAXNAMELEN-1);
            else return -E_BAD_PATH; 
        }
        while (*p == '/') p++;
    }

    // Phase 2: Reconstruct the path from components
    char *write_ptr = path_buf;
    if (is_absolute) {
        *write_ptr++ = '/';
    }

    for (int i = 0; i < comp_idx; i++) {
        if (i > 0) { // Need a separator for components after the first
            if (write_ptr - path_buf >= MAXPATHLEN - 1) return -E_BAD_PATH;
            *write_ptr++ = '/';
        } else if (!is_absolute && comp_idx > 0 && i == 0) {
            // First component of a relative path, no leading slash needed from here.
        } else if (is_absolute && comp_idx > 0 && i == 0 && write_ptr == path_buf + 1) {
            // Absolute path, first component after root '/', no extra slash if write_ptr is right after it.
        }


        int len = _mystrlen(components[i]);
        if ((write_ptr - path_buf) + len >= MAXPATHLEN) return -E_BAD_PATH;
        memcpy(write_ptr, components[i], len);
        write_ptr += len;
    }
    *write_ptr = '\0';

    // Final fixups for empty or root results
    if (path_buf[0] == '\0') {
        if (is_absolute) _mystrcpy(path_buf, "/");
        else _mystrcpy(path_buf, ".");
    } else if (is_absolute && path_buf[0] == '/' && path_buf[1] == '\0' && comp_idx > 0) {
        // This case means something like "/foo/.." resolved to "/".
        // If comp_idx is > 0, it means there *were* components that simplified away.
        // If comp_idx became 0 (e.g. /.. or /foo/..), path_buf should correctly be just "/"
        // No specific action needed here if reconstruction is correct.
    } else if (is_absolute && write_ptr == path_buf) { 
        // This can happen if input was "/" and comp_idx remained 0.
        // Ensure it's at least "/".
        path_buf[0] = '/'; path_buf[1] = '\0';
    }

    return 0;
}

// Overview:
//  Close a file descriptor
int file_close(struct Fd *fd) {
	int r;
	struct Filefd *ffd;
	void *va;
	u_int size, fileid;
	u_int i;

	ffd = (struct Filefd *)fd;
	fileid = ffd->f_fileid;
	size = ffd->f_file.f_size;

	// Set the start address storing the file's content.
	va = fd2data(fd);

	// Tell the file server the dirty page.
	for (i = 0; i < size; i += PTMAP) {
		if ((r = fsipc_dirty(fileid, i)) < 0) {
			debugf("cannot mark pages as dirty\n");
			return r;
		}
	}

	// Request the file server to close the file with fsipc.
	if ((r = fsipc_close(fileid)) < 0) {
		debugf("cannot close the file\n");
		return r;
	}

	// Unmap the content of file, release memory.
	if (size == 0) {
		return 0;
	}
	for (i = 0; i < size; i += PTMAP) {
		if ((r = syscall_mem_unmap(0, (void *)(va + i))) < 0) {
			debugf("cannont unmap the file\n");
			return r;
		}
	}
	return 0;
}

// Overview:
//  Read 'n' bytes from 'fd' at the current seek position into 'buf'. Since files
//  are memory-mapped, this amounts to a memcpy() surrounded by a little red
//  tape to handle the file size and seek pointer.
static int file_read(struct Fd *fd, void *buf, u_int n, u_int offset) {
	u_int size;
	struct Filefd *f;
	f = (struct Filefd *)fd;

	// Avoid reading past the end of file.
	size = f->f_file.f_size;

	if (offset > size) {
		return 0;
	}

	if (offset + n > size) {
		n = size - offset;
	}

	memcpy(buf, (char *)fd2data(fd) + offset, n);
	return n;
}

// Overview:
//  Find the virtual address of the page that maps the file block
//  starting at 'offset'.
int read_map(int fdnum, u_int offset, void **blk) {
	int r;
	void *va;
	struct Fd *fd;

	if ((r = fd_lookup(fdnum, &fd)) < 0) {
		return r;
	}

	if (fd->fd_dev_id != devfile.dev_id) {
		return -E_INVAL;
	}

	va = fd2data(fd) + offset;

	if (offset >= MAXFILESIZE) {
		return -E_NO_DISK;
	}

	if (!(vpd[PDX(va)] & PTE_V) || !(vpt[VPN(va)] & PTE_V)) {
		return -E_NO_DISK;
	}

	*blk = (void *)va;
	return 0;
}

// Overview:
//  Write 'n' bytes from 'buf' to 'fd' at the current seek position.
static int file_write(struct Fd *fd, const void *buf, u_int n, u_int offset) {
	int r;
	u_int tot;
	struct Filefd *f;

	f = (struct Filefd *)fd;

	// Don't write more than the maximum file size.
	tot = offset + n;

	if (tot > MAXFILESIZE) {
		return -E_NO_DISK;
	}
	// Increase the file's size if necessary
	if (tot > f->f_file.f_size) {
		if ((r = ftruncate(fd2num(fd), tot)) < 0) {
			return r;
		}
	}

	// Write the data
	memcpy((char *)fd2data(fd) + offset, buf, n);
	return n;
}

static int file_stat(struct Fd *fd, struct Stat *st) {
	struct Filefd *f;

	f = (struct Filefd *)fd;

	strcpy(st->st_name, f->f_file.f_name);
	st->st_size = f->f_file.f_size;
	st->st_isdir = f->f_file.f_type == FTYPE_DIR;
	return 0;
}

// Overview:
//  Truncate or extend an open file to 'size' bytes
int ftruncate(int fdnum, u_int size) {
	int i, r;
	struct Fd *fd;
	struct Filefd *f;
	u_int oldsize, fileid;

	if (size > MAXFILESIZE) {
		return -E_NO_DISK;
	}

	if ((r = fd_lookup(fdnum, &fd)) < 0) {
		return r;
	}

	if (fd->fd_dev_id != devfile.dev_id) {
		return -E_INVAL;
	}

	f = (struct Filefd *)fd;
	fileid = f->f_fileid;
	oldsize = f->f_file.f_size;
	f->f_file.f_size = size;

	if ((r = fsipc_set_size(fileid, size)) < 0) {
		return r;
	}

	void *va = fd2data(fd);

	// Map any new pages needed if extending the file
	for (i = ROUND(oldsize, PTMAP); i < ROUND(size, PTMAP); i += PTMAP) {
		if ((r = fsipc_map(fileid, i, va + i)) < 0) {
			int _r = fsipc_set_size(fileid, oldsize);
			if (_r < 0) {
				return _r;
			}
			return r;
		}
	}

	// Unmap pages if truncating the file
	for (i = ROUND(size, PTMAP); i < ROUND(oldsize, PTMAP); i += PTMAP) {
		if ((r = syscall_mem_unmap(0, (void *)(va + i))) < 0) {
			user_panic("ftruncate: syscall_mem_unmap %08x: %d\n", va + i, r);
		}
	}

	return 0;
}

// Overview:
//  Delete a file or directory.
int remove(const char *path) {
	// Call fsipc_remove.

	/* Exercise 5.13: Your code here. */
	return fsipc_remove(path);
}

// Overview:
//  Synchronize disk with buffer cache
int sync(void) {
	return fsipc_sync();
}


int _mystrncpy(char* dest, const char* src, int count)
{
	char* start = dest; 
	while (count && (*dest++ = *src++)) 
	{
		count--;
	}
	if (count) 
	{
		while (--count)
		{
			*dest++ = '\0';
		}
	}
	return 0; 
}

int _mystrncmp(const char *s1, const char *s2, int n) {
    size_t i = 0;

    if (n < 0) return 0; 

    while (i < (size_t)n && s1[i] != '\0' && s2[i] != '\0') {
        if (s1[i] != s2[i]) {
            return (unsigned char)s1[i] - (unsigned char)s2[i];
        }
        i++;
    }

    if (i < (size_t)n) { 
            return (unsigned char)s1[i] - (unsigned char)s2[i];
    }
    return 0; 
}

int _mystrcmp(const char *str1, const char *str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *(unsigned char *)str1 - *(unsigned char *)str2;
}

int _mystrcat(char* dest, const char* src) {
    char* ptr = dest;

    // 找到 dest 的末尾
    while (*ptr != '\0') {
        ptr++;
    }

    // 将 src 的内容复制到 dest 的末尾
    while (*src != '\0') {
        *ptr = *src;
        ptr++;
        src++;
    }

    // 添加字符串结束符
    *ptr = '\0';

    return 0;
}

int _mystrcpy(char* dest, const char* src) {
    char* original_dest = dest; // 保存目标字符串的起始地址
    while ((*dest++ = *src++) != '\0'); // 逐字符复制，直到遇到 '\0'
    return 0; // 返回目标字符串的起始地址
}

int _mystrlen(const char *str) {
    size_t length = 0;
    while (str[length] != '\0') {
        length++;
    }
    return length;
}
