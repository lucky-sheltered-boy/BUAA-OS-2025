#include <lib.h>

int flag_r;
int flag_f;

void rm(char *path) {
    int fd;
    struct Stat st;
    if ((fd = open(path, O_RDONLY)) < 0) {
        if (!flag_f) {
            printf("rm: cannot remove '%s': No such file or directory\n", path);
        }
        return;
    }
    close(fd);
    stat(path, &st);
    if (st.st_isdir && !flag_r) {
        printf("rm: cannot remove '%s': Is a directory\n", path);
    }
    char cwd[1024] = {0};
    syscall_get_cwd(cwd);
    char finalpath[1024] = {0};
    get_final_path(cwd, path, finalpath);
    //printf("rm finalpath: %s\n", finalpath);
    remove(finalpath);
}

int get_final_path(const char *cwd, const char *path, char *finalpath) {
    if (!cwd || !path || !finalpath) {
        return -1; // Invalid arguments
    }

    char constructed_path[MAXPATHLEN * 2]; // Intermediate buffer for path construction

    // 1. Determine if 'path' is absolute or relative and construct initial full path
    if (path[0] == '/') { // Absolute path
        if (mystrlen(path) >= MAXPATHLEN) {
            // printf("Error: Absolute path too long.\n"); // Optional debug
        }
        mystrcpy(constructed_path, path);
        // As per your spec: "绝对路径，此时将这个绝对路径复制到第三个参数finalpath即可，返回0"
        // This means no stat check for absolute paths here.
        // Normalization is still good practice.
	//printf("rel is abs, raw finalpath: %s\n", constructed_path);
    } else { // Relative path
        // Construct full path: cwd + "/" + path
        if (mystrlen(cwd) + 1 + mystrlen(path) + 1 > sizeof(constructed_path)) { // +1 for potential slash, +1 for null
            // printf("Error: Constructed relative path too long.\n");
        }
        mystrcpy(constructed_path, cwd);
        // Add slash if cwd is not "/" and path is not empty
        if (mystrcmp(cwd, "/") != 0 && constructed_path[mystrlen(constructed_path) - 1] != '/') {
            mystrcat(constructed_path, "/");
        } else if (mystrcmp(cwd, "/") == 0 && mystrlen(constructed_path) > 1) { 
            // If cwd was "/" and something got appended making it "//path", fix to "/path"
            // This case is usually handled by normalize_path later.
            // More simply, if cwd is "/", just don't add another slash if path is not empty.
        }
        mystrcat(constructed_path, path);
	//printf("rel is rel, raw finalpath: %s\n", constructed_path);
        // Normalize the constructed path (handles ".", "..", "//")
    }
        if (normalize_path(constructed_path) < 0) {
            // printf("Error: Failed to normalize constructed path '%s'\n", temp_path);
        }
        
        // For relative paths, after normalization, perform stat check

        // Path exists and is a directory
        mystrcpy(finalpath, constructed_path);
        return 0; // Success
    
}

// normalize_path function (copied from previous response for completeness if not in a shared lib)
// Ensure MAXNAMELEN and MAXPATHLEN are defined (typically from fs.h)
// Ensure mystrcmp, mystrncpy, mymemcpy, mystrlen are available
int normalize_path(char *path_buf) {
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
        char current_comp_val[128];
        char *c_ptr = current_comp_val;
        while (*p != '/' && *p != '\0') {
            if (c_ptr - current_comp_val < 128 - 1) *c_ptr++ = *p;
            p++;
        }
        *c_ptr = '\0';

        if (mystrcmp(current_comp_val, "..") == 0) {
            if (comp_idx > 0 && mystrcmp(components[comp_idx - 1], "..") != 0) {
                comp_idx--; // Pop if last wasn't ".."
            } else if (!is_absolute) { // Relative path: push ".." or if stack top is ".." push another
                if (comp_idx < 128) mystrncpy(components[comp_idx++], "..", 128-1);
                else return -E_BAD_PATH; // Path too complex/long
            }
            // If absolute and comp_idx is 0 (or was ".."), ".." from root is ignored or handled by pop
        } else if (mystrcmp(current_comp_val, ".") != 0 && current_comp_val[0] != '\0') {
            if (comp_idx < 128) mystrncpy(components[comp_idx++], current_comp_val, 128-1);
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


        int len = mystrlen(components[i]);
        if ((write_ptr - path_buf) + len >= MAXPATHLEN) return -E_BAD_PATH;
        memcpy(write_ptr, components[i], len);
        write_ptr += len;
    }
    *write_ptr = '\0';

    // Final fixups for empty or root results
    if (path_buf[0] == '\0') {
        if (is_absolute) mystrcpy(path_buf, "/");
        else mystrcpy(path_buf, ".");
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
int mystrncpy(char* dest, const char* src, int count)
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

int mystrncmp(const char *s1, const char *s2, int n) {
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

int mystrcmp(const char *str1, const char *str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *(unsigned char *)str1 - *(unsigned char *)str2;
}

int mystrcat(char* dest, const char* src) {
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

int mystrcpy(char* dest, const char* src) {
    char* original_dest = dest; // 保存目标字符串的起始地址
    while ((*dest++ = *src++) != '\0'); // 逐字符复制，直到遇到 '\0'
    return 0; // 返回目标字符串的起始地址
}

int mystrlen(const char *str) {
    size_t length = 0;
    while (str[length] != '\0') {
        length++;
    }
    return length;
}


int main(int argc, char **argv) {
    char s_r[5] = "-r";
    char s_rf[5] = "-rf";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], s_r) == 0) {
            argv[i] = 0;
            flag_r = 1;
        } else if (strcmp(argv[i], s_rf) == 0) {
            argv[i] = 0;
            flag_f = 1;
            flag_r = 1;
        }
    }

    if (argc < 2) {
        printf("nothing to rm\n");
    } else {
        for (int i = 1; i < argc; ++i) {
            if (argv[i] == 0) {
                continue;
            }
            rm(argv[i]);
        }
    }
}
