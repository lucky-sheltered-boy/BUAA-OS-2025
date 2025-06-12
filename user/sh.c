#include <args.h>
#include <lib.h>
#include <fs.h>     // Added for O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC, O_APPEND
//#include <stdlib.h> // Commented out to avoid exit conflict initially

// --- Configuration ---
#define MAX_INPUT_BUF 1024
#define MAX_TOKEN_LEN 1024
#define MAX_CMD_ARGS 128
#define MAX_VAR_NAME_LEN 16
#define MAX_VAR_VALUE_LEN 16
#define MAX_SHELL_VARS 128 // Arbitrary limit
#define MAX_EXPANDED_STR_LEN (MAX_TOKEN_LEN * 2) // Or some reasonable upper bound

char expansion_buffer_pool[100][MAX_EXPANDED_STR_LEN]; // Pool for expanded strings
int expansion_buffer_pool_index = 0;
char* expand_string_variables(char *input_str);

typedef struct {
    char name[MAX_VAR_NAME_LEN + 1];
    char value[MAX_VAR_VALUE_LEN + 1];
    int is_exported; // 0 for local, 1 for environment
    int is_readonly; // 0 for writable, 1 for read-only
    int is_set;      // 0 if slot is free or unset, 1 if set (even if value is empty)
} ShellVar;

static ShellVar shell_vars[MAX_SHELL_VARS];
static int num_set_vars = 0; // Optional: to quickly check if full or for find_free_slot

void init_shell_vars(void);
ShellVar* find_variable(const char *name);
int set_variable(const char *name, const char *value, int export_flag, int readonly_flag, int update_flags_if_exists);
int unset_variable(const char *name);
void print_all_variables(void);
char* get_variable_value(const char *name); // For expansion

// --- Forward Declarations for AST node types ---
typedef struct ASTNode ASTNode;

// --- AST Node Types Enum ---
typedef enum {
    NODE_ILLEGAL = 0,
    NODE_COMMAND,
    NODE_PIPELINE,
    NODE_LIST_SEMI,  // For ';'
    NODE_LIST_AMP,   // For '&' (background)
    NODE_AND,        // For '&&'
    NODE_OR,         // For '||'
} ASTNodeType;

// --- Token Types Enum (based on EBNF) ---
typedef enum {
    TOKEN_ERROR = 0,   // Error or uninitialized
    TOKEN_EOF = 1,     // End of input (actual end)
    TOKEN_EOL = 2,     // End of line (newline or effective end via '#')

    TOKEN_WORD,        // Command, argument, filename

    TOKEN_PIPE,        // |
    TOKEN_SEMI,        // ;
    TOKEN_AMP,         // & (background task)
    TOKEN_AND,         // &&
    TOKEN_OR,          // ||
    TOKEN_REDIR_IN,    // <
    TOKEN_REDIR_OUT,   // >
    TOKEN_REDIR_APP,   // >>
} TokenType;

// --- Token Structure ---
typedef struct {
    TokenType type;
    char value[MAX_TOKEN_LEN]; // String value of the token
} Token;


// --- Redirection Structure ---
typedef enum {
    REDIR_TYPE_IN,   // <
    REDIR_TYPE_OUT,  // >
    REDIR_TYPE_APP,  // >>
} RedirType;

typedef struct RedirNode {
    RedirType type;
    char *filename;
    struct RedirNode *next;
} RedirNode;


// --- AST Node Structures ---
typedef struct {
    char *argv[MAX_CMD_ARGS];
    int argc;
    RedirNode *redirects; // Linked list of redirections
} CMDNodeData;

typedef struct {
    ASTNode *left;
    ASTNode *right;
} BinaryOpNodeData; // For Pipeline, List, And, Or

struct ASTNode {
    ASTNodeType type;
    union {
        CMDNodeData command;
        BinaryOpNodeData binary_op;
    } data;
};

// --- Forward Declarations for Parser and Executor ---
ASTNode *parse_list(void); 
void readline(char *buf, u_int n, int interactive); 
void free_ast_resources(void); // To reset static allocators

// --- Static Allocators (Simple version for MOS) ---
char strdup_pool[100][1000] = {0}; 
int strdup_pool_index = 0;

ASTNode astnode_pool[100] = {0}; 
int astnode_pool_index = 0;

RedirNode redirnode_pool[100] = {0}; 
int redirnode_pool_index = 0;

void reset_allocators() {
    strdup_pool_index = 0;
    astnode_pool_index = 0;
    redirnode_pool_index = 0;
    expansion_buffer_pool_index = 0;
}

char *user_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    if (len > 1000) {
        user_panic("strdup: string too long");
    }
    if (strdup_pool_index >= 100) {
        user_panic("strdup_pool out of space");
    }
    char *new_s = strdup_pool[strdup_pool_index++];
    memcpy(new_s, s, len); 
    return new_s;
}

ASTNode *alloc_ast_node(ASTNodeType type) {
    if (astnode_pool_index >= 100) {
        user_panic("astnode_pool out of space");
    }
    ASTNode *node = &astnode_pool[astnode_pool_index++];
    memset(node, 0, sizeof(ASTNode)); 
    node->type = type;
    return node;
}

RedirNode *alloc_redir_node() {
    if (redirnode_pool_index >= 100) {
        user_panic("redirnode_pool out of space");
    }
    RedirNode *node = &redirnode_pool[redirnode_pool_index++];
    memset(node, 0, sizeof(RedirNode)); 
    return node;
}


// --- Tokenizer Globals ---
static const char *current_pos; 
static Token current_token;
static Token peeked_token;
static int has_peeked_token;


// --- Tokenizer Implementation ---
void skip_whitespace_and_comments() {
    while (*current_pos) {
        if (strchr(" \t\r\n", *current_pos)) {
            current_pos++;
        } else if (*current_pos == '#') {
            while (*current_pos && *current_pos != '\n') {
                current_pos++;
            }
             if (*current_pos == '\n') {
                 current_pos++; 
             }
        } else {
            break;
        }
    }
}

Token get_next_raw_token() {
    Token token;
    memset(&token, 0, sizeof(Token));
    token.type = TOKEN_ERROR;

    skip_whitespace_and_comments();

    if (*current_pos == '\0') {
        token.type = TOKEN_EOF;
        return token;
    }

    if (mystrncmp(current_pos, "&&", 2) == 0) {
        token.type = TOKEN_AND;
        mystrncpy(token.value, "&&", MAX_TOKEN_LEN -1);
        token.value[MAX_TOKEN_LEN-1] = '\0';
        current_pos += 2;
    } else if (mystrncmp(current_pos, "||", 2) == 0) {
        token.type = TOKEN_OR;
        mystrncpy(token.value, "||", MAX_TOKEN_LEN-1);
        token.value[MAX_TOKEN_LEN-1] = '\0';
        current_pos += 2;
    } else if (mystrncmp(current_pos, ">>", 2) == 0) {
        token.type = TOKEN_REDIR_APP;
        mystrncpy(token.value, ">>", MAX_TOKEN_LEN-1);
        token.value[MAX_TOKEN_LEN-1] = '\0';
        current_pos += 2;
    }
    else if (*current_pos == '|') {
        token.type = TOKEN_PIPE;
        token.value[0] = '|'; token.value[1] = '\0';
        current_pos++;
    } else if (*current_pos == ';') {
        token.type = TOKEN_SEMI;
        token.value[0] = ';'; token.value[1] = '\0';
        current_pos++;
    } else if (*current_pos == '&') {
        token.type = TOKEN_AMP;
        token.value[0] = '&'; token.value[1] = '\0';
        current_pos++;
    } else if (*current_pos == '<') {
        token.type = TOKEN_REDIR_IN;
        token.value[0] = '<'; token.value[1] = '\0';
        current_pos++;
    } else if (*current_pos == '>') {
        token.type = TOKEN_REDIR_OUT;
        token.value[0] = '>'; token.value[1] = '\0';
        current_pos++;
    }
    else {
        token.type = TOKEN_WORD;
        int i = 0;
        while (*current_pos &&
               !strchr(" \t\r\n", *current_pos) &&
               !strchr("|;&<>#", *current_pos) && 
               i < MAX_TOKEN_LEN - 1) {
             if (mystrncmp(current_pos, "&&", 2) == 0 || mystrncmp(current_pos, "||", 2) == 0 || mystrncmp(current_pos, ">>", 2) == 0) {
                break;
            }
            token.value[i++] = *current_pos++;
        }
        token.value[i] = '\0';
        if (i == 0) { 
             if (*current_pos == '\0') token.type = TOKEN_EOF;
             else token.type = TOKEN_ERROR; 
        }
    }
    return token;
}

void tokenizer_init(const char *input) { 
    current_pos = input;
    has_peeked_token = 0;
    current_token = get_next_raw_token(); // Prime the first token
}

Token consume_token() {
    Token old_current = current_token;
    if (current_token.type == TOKEN_EOF) return old_current; 

    if (has_peeked_token) {
        current_token = peeked_token;
        has_peeked_token = 0;
    } else {
        current_token = get_next_raw_token();
    }
    return old_current;
}

Token peek() {
    if (current_token.type == TOKEN_EOF) return current_token;

    if (!has_peeked_token) {
        peeked_token = get_next_raw_token(); 
        has_peeked_token = 1;
    }
    return peeked_token; 
}


// --- Parser (Recursive Descent) ---
ASTNode *parse_and_or(void);
ASTNode *parse_pipeline(void);
ASTNode *parse_command(void);

ASTNode *parse_line() {
    if (current_token.type == TOKEN_EOF || current_token.type == TOKEN_EOL) {
        return NULL;
    }
    return parse_list();
}

ASTNode *parse_list() {
    ASTNode *node = parse_and_or();
    if (!node) { 
        return NULL;
    }

    while (current_token.type == TOKEN_SEMI || current_token.type == TOKEN_AMP) {
        TokenType op_type = current_token.type;
        consume_token();

        if (current_token.type == TOKEN_EOF || current_token.type == TOKEN_EOL) { 
            ASTNode *new_list_node = alloc_ast_node(op_type == TOKEN_SEMI ? NODE_LIST_SEMI : NODE_LIST_AMP);
            new_list_node->data.binary_op.left = node;
            new_list_node->data.binary_op.right = NULL;
            node = new_list_node;
            break; 
        }

        ASTNode *right_node = parse_and_or();
        if (!right_node) {
            debugf("Syntax error after '%s'\n", op_type == TOKEN_SEMI ? ";" : "&");
            return NULL; 
        }

        ASTNode *new_list_node = alloc_ast_node(op_type == TOKEN_SEMI ? NODE_LIST_SEMI : NODE_LIST_AMP);
        new_list_node->data.binary_op.left = node;
        new_list_node->data.binary_op.right = right_node;
        node = new_list_node;
    }
    return node;
}

ASTNode *parse_and_or() {
    ASTNode *node = parse_pipeline();
    if (!node) return NULL;

    while (current_token.type == TOKEN_AND || current_token.type == TOKEN_OR) {
        TokenType op_type = current_token.type;
        consume_token();
        ASTNode *right_node = parse_pipeline();
        if (!right_node) {
            debugf("Syntax error: '%s' not followed by pipeline\n", op_type == TOKEN_AND ? "&&" : "||");
            return NULL;
        }
        ASTNode *new_op_node = alloc_ast_node(op_type == TOKEN_AND ? NODE_AND : NODE_OR);
        new_op_node->data.binary_op.left = node;
        new_op_node->data.binary_op.right = right_node;
        node = new_op_node;
    }
    return node;
}

ASTNode *parse_pipeline() {
    ASTNode *node = parse_command();
    if (!node) return NULL;

    while (current_token.type == TOKEN_PIPE) {
        consume_token();
        ASTNode *right_node = parse_command();
        if (!right_node) {
            debugf("Syntax error: '|' not followed by command\n");
            return NULL;
        }
        ASTNode *new_pipe_node = alloc_ast_node(NODE_PIPELINE);
        new_pipe_node->data.binary_op.left = node;
        new_pipe_node->data.binary_op.right = right_node;
        node = new_pipe_node;
    }
    return node;
}

ASTNode *parse_command() {
    if (current_token.type != TOKEN_WORD &&
        current_token.type != TOKEN_REDIR_IN &&
        current_token.type != TOKEN_REDIR_OUT &&
        current_token.type != TOKEN_REDIR_APP) {
        if (current_token.type == TOKEN_EOF || current_token.type == TOKEN_EOL) return NULL;
        return NULL; 
    }

    ASTNode *cmd_node_ast = alloc_ast_node(NODE_COMMAND);
    CMDNodeData *cmd_data = &cmd_node_ast->data.command;
    RedirNode **next_redir_ptr = &cmd_data->redirects;

    while (1) { // Changed to infinite loop, break out explicitly
        if (current_token.type == TOKEN_WORD) {
            if (cmd_data->argc < MAX_CMD_ARGS - 1) {
		     // Expand variables in the token's value
                char *expanded_arg = expand_string_variables(current_token.value);
                cmd_data->argv[cmd_data->argc++] = expanded_arg; // user_strdup is now done by expand_string_variables
            } else {
                debugf("Too many arguments for command\n");
                return NULL; 
            }
            consume_token();
        } else if (current_token.type == TOKEN_REDIR_IN ||
                   current_token.type == TOKEN_REDIR_OUT ||
                   current_token.type == TOKEN_REDIR_APP) {
            TokenType redir_op_type = current_token.type;
            consume_token(); 

            if (current_token.type != TOKEN_WORD) {
                debugf("Syntax error: Redirection operator not followed by filename\n");
                return NULL; 
            }

            RedirNode *redir_node = alloc_redir_node();
            if (redir_op_type == TOKEN_REDIR_IN) redir_node->type = REDIR_TYPE_IN;
            else if (redir_op_type == TOKEN_REDIR_OUT) redir_node->type = REDIR_TYPE_OUT;
	    else if (redir_op_type == TOKEN_REDIR_APP) redir_node->type = REDIR_TYPE_APP;
	     // Expand variables in the filename
            char *expanded_filename = expand_string_variables(current_token.value);
            redir_node->filename = expanded_filename; // user_strdup is now done by expand_string_variables
            consume_token();


            *next_redir_ptr = redir_node;
            next_redir_ptr = &redir_node->next;
        } else {
            break; // Not a word or redirection, end of simple command
        }
    }
    cmd_data->argv[cmd_data->argc] = NULL; 

    if (cmd_data->argc == 0 && cmd_data->redirects == NULL) {
         return NULL;
    }
    return cmd_node_ast;
}

void reset_expansion_buffer_pool() {
    expansion_buffer_pool_index = 0;
}

char *get_expansion_buffer() {
    if (expansion_buffer_pool_index >= 100) {
        user_panic("expansion_buffer_pool out of space");
    }
    return expansion_buffer_pool[expansion_buffer_pool_index++];
}

char * expand_string_variables( char *input_str) {
    if (!input_str || !strchr(input_str, '$')) { // Quick check: if no '$', return original (or a copy)
        return user_strdup(input_str); // Return a copy from strdup_pool
    }

    char *output_buf = get_expansion_buffer(); // Get a buffer from the expansion pool
    output_buf[0] = '\0'; // Start with an empty string
    char *out_ptr = output_buf;
    const char *in_ptr = input_str;

    while (*in_ptr) {
        if (*in_ptr == '$') {
            in_ptr++; // Skip the '$'
            char var_name[MAX_VAR_NAME_LEN + 1];
            int i = 0;
            // Variable names: alphanumeric and underscore, first char not a digit (C-like)
            // For simplicity, let's allow any char until a non-var char or MAX_VAR_NAME_LEN
            // Bash rules are more complex (e.g. ${var}, $?, $#)
            // For MOS, assume simple $VARNAME.
            while (*in_ptr &&
                   i < MAX_VAR_NAME_LEN &&
                   // Define what constitutes a valid variable name character.
                   // For simplicity: not whitespace, not another '$', not operators like '|', ';', '<', '>', '&'
                   // and not path separators like '/'.
                   !strchr(" \t\r\n$|;&<>/", *in_ptr)
                   ) {
                var_name[i++] = *in_ptr++;
            }
            var_name[i] = '\0';

            if (i > 0) { // A variable name was actually parsed
                const char *var_value = get_variable_value(var_name);
                if (var_value) {
                    size_t val_len = mystrlen(var_value);
                    if ((out_ptr - output_buf) + val_len < MAX_EXPANDED_STR_LEN) {
                        mystrcpy(out_ptr, var_value);
                        out_ptr += val_len;
                    } else { /* Buffer overflow for expanded string, handle error or truncate */ }
                }
                // If var_value is NULL (not found), it expands to nothing (empty string),
                // so we just don't append anything.
            } else {
                // Case: just '$' or '$' followed by a delimiter immediately. Treat '$' literally.
                if ((out_ptr - output_buf) < MAX_EXPANDED_STR_LEN -1) {
                    *out_ptr++ = '$';
                     // If in_ptr didn't move (e.g. '$' at end of string, or '$$'),
                     // we need to ensure we don't get stuck in a loop if in_ptr pointed to the char after '$'
                     // The outer loop's *in_ptr check and increment will handle moving past the delimiter or end.
                }
            }
        } else {
            if ((out_ptr - output_buf) < MAX_EXPANDED_STR_LEN - 1) {
                *out_ptr++ = *in_ptr++;
            } else {
                in_ptr++; // Skip char if buffer is full, or break
            }
        }
    }
    *out_ptr = '\0';
    return output_buf;
}

int is_inner_cmd(CMDNodeData *cmd) {
	if (mystrcmp(cmd->argv[0], "cd") == 0 || 
	    mystrcmp(cmd->argv[0], "pwd") == 0 ||
	    mystrcmp(cmd->argv[0], "exit") == 0 ||
	    mystrcmp(cmd->argv[0], "declare") == 0 ||
	    mystrcmp(cmd->argv[0], "unset") == 0 ) {
		return 1;
	} else {
		return 0;
	}
}

void execute_inner_cmd(CMDNodeData *cmd) {
	if (mystrcmp(cmd->argv[0], "pwd") == 0) {
		if (cmd->argc > 1) {
			printf("pwd: expected 0 arguments; got %d\n", cmd->argc - 1);
		} else {
			char buf[1024] = {0};
			syscall_get_cwd(buf);
			printf("%s\n", buf);
		}
	} else if (mystrcmp(cmd->argv[0], "cd") == 0) {
		char finalpath[1024] = {0};
		if (cmd->argc == 1) {
			mystrcpy(finalpath, "/");
		} else if (cmd->argc == 2) {
			char cwd[1024] = {0};
			syscall_get_cwd(cwd);
			int r;
			if ((r = get_final_path(cwd, cmd->argv[1], finalpath)) == 0) {
				//printf("absolute path: %s\n", finalpath);
				syscall_set_cwd(finalpath);
			} else {
				if (r == 1) {
					printf("cd: The directory '%s' does not exist\n", cmd->argv[1]);
				} else if (r == 2) {
					printf("cd: '%s' is not a directory\n", cmd->argv[1]);
				} else if (r == -1) {
					printf("cwd or relcwd does not exists\n");
				} else if (r == -2) {
					printf("path is too long\n");
				} else if (r == -3) {
					printf("fail to normalize path\n");
				}	
			}
		} else if (cmd->argc > 2) {
			printf("Too many args for cd command\n");
		}
	} else if (mystrcmp(cmd->argv[0], "exit") == 0) {
		exit();
	} else if (mystrcmp(cmd->argv[0], "declare") == 0) {
		int export_f = 0;
       		int readonly_f = 0;
        	int arg_idx = 1;
        	char *name_val_pair = NULL;

        	// Parse flags
        	while (cmd->argv[arg_idx] && cmd->argv[arg_idx][0] == '-') {
            		if (mystrcmp(cmd->argv[arg_idx], "-x") == 0) export_f = 1;
            		else if (mystrcmp(cmd->argv[arg_idx], "-r") == 0) readonly_f = 1;
			else if (mystrcmp(cmd->argv[arg_idx], "-xr") == 0 ||
				 mystrcmp(cmd->argv[arg_idx], "-rx") == 0) {
				export_f = 1;
				readonly_f = 1;
			}
            		else {
                		printf("declare: invalid option %s\n", cmd->argv[arg_idx]);
                		return; // Indicate error if builtins had return values
            		}
            		arg_idx++;
        	}

        	if (cmd->argv[arg_idx]) { // NAME[=VALUE] part
            		name_val_pair = cmd->argv[arg_idx];
        	}

        	if (!name_val_pair) { // Just "declare" or "declare -xr"
            		print_all_variables();
        	} else {
            		char name[MAX_VAR_NAME_LEN + 1];
            		char value_buf[MAX_VAR_VALUE_LEN + 1]; // Buffer for value if parsed
            		char *value_ptr = NULL;

            		char *eq_ptr = strchr(name_val_pair, '=');
            		if (eq_ptr) { // NAME=VALUE
                		int name_len = eq_ptr - name_val_pair;
                		if (name_len > MAX_VAR_NAME_LEN) { /* error */ return; }
                		mystrncpy(name, name_val_pair, name_len);
                		name[name_len] = '\0';
                		value_ptr = eq_ptr + 1; // Can be empty string
                		if (mystrlen(value_ptr) > MAX_VAR_VALUE_LEN) { /* error */ return; }
                		mystrcpy(value_buf, value_ptr);
                		value_ptr = value_buf;

            		} else { // Just NAME
                		if (mystrlen(name_val_pair) > MAX_VAR_NAME_LEN) { /* error */ return; }
                			mystrcpy(name, name_val_pair);
                			value_ptr = ""; // Default to empty string
            		}
            		set_variable(name, value_ptr, export_f, readonly_f, 1);
        	}
	} else if (mystrcmp(cmd->argv[0], "unset") == 0) {
        	if (cmd->argc != 2) {
            		printf("unset: usage: unset NAME\n");
            		return;
        	}
        	unset_variable(cmd->argv[1]);
    	}
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
            return -2; // Path too long
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
            return -2;
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
            return -3; // Normalization error
        }
        
        // For relative paths, after normalization, perform stat check
        struct Stat st;
        int r_stat = stat(constructed_path, &st); // stat uses the (now absolute) constructed_path

        if (r_stat < 0) {
            // Error from stat typically means not found (check specific error codes if MOS stat provides them)
            // Assuming -E_NOT_FOUND or similar is returned by stat()
            return 1; // "does not exist"
        }

        if (st.st_isdir == 0) { // FTYPE_DIR is 1, regular file is 0
            return 2; // "is not a directory"
        }

        // Path exists and is a directory
        mystrcpy(finalpath, constructed_path);
        return 0; // Success
    
}

// normalize_path function (copied from previous response for completeness if not in a shared lib)
// Ensure MAXNAMELEN and MAXPATHLEN are defined (typically from fs.h)
// Ensure mystrcmp, mystrncpy, mymemcpy, mystrlen are available
int normalize_path(char *path_buf) {
    if (path_buf == NULL) return -1;

    char components[MAX_CMD_ARGS][MAXNAMELEN]; 
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

        if (mystrcmp(current_comp_val, "..") == 0) {
            if (comp_idx > 0 && mystrcmp(components[comp_idx - 1], "..") != 0) {
                comp_idx--; // Pop if last wasn't ".."
            } else if (!is_absolute) { // Relative path: push ".." or if stack top is ".." push another
                if (comp_idx < MAX_CMD_ARGS) mystrncpy(components[comp_idx++], "..", MAXNAMELEN-1);
                else return -E_BAD_PATH; // Path too complex/long
            }
            // If absolute and comp_idx is 0 (or was ".."), ".." from root is ignored or handled by pop
        } else if (mystrcmp(current_comp_val, ".") != 0 && current_comp_val[0] != '\0') {
            if (comp_idx < MAX_CMD_ARGS) mystrncpy(components[comp_idx++], current_comp_val, MAXNAMELEN-1);
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

// --- AST Executor ---
void execute_ast(ASTNode *node) {
    if (!node) {
        return;
    }

    int child_pid;
    int pipe_fds[2];

    switch (node->type) {
        case NODE_COMMAND: {
            CMDNodeData *cmd = &node->data.command;
            if (cmd->argc == 0 && cmd->redirects == NULL) { // Should be caught by parser
                return;
            }
            if (cmd->argc == 0) { 
                debugf("sh: missing command for redirection\n");
                return;
            }
	    if (is_inner_cmd(cmd)) {
	    	execute_inner_cmd(cmd);
		break;
	    }

            child_pid = fork();
            if (child_pid < 0) {
                user_panic("execute_ast: fork for command failed");
            }

            if (child_pid == 0) { // Child process
                RedirNode *redir = cmd->redirects;
                while (redir) {
                    int open_flags = 0;
                    int target_fd_std = -1;

                    if (redir->type == REDIR_TYPE_IN) {
                        open_flags = O_RDONLY;
                        target_fd_std = 0; 
                    } else if (redir->type == REDIR_TYPE_OUT) {
                        open_flags = O_WRONLY | O_CREAT | O_TRUNC;
                        target_fd_std = 1; 
                    } else if (redir->type == REDIR_TYPE_APP) {
                        open_flags = O_WRONLY | O_CREAT | O_APPEND; 
                        target_fd_std = 1; 
                    }

                    int opened_fd = open(redir->filename, open_flags);
                    if (opened_fd < 0) {
                        printf("sh: cannot open %s\n", redir->filename); // Use printf for user messages
                        exit(); 
                    }
                    dup(opened_fd, target_fd_std);
                    close(opened_fd);
                    redir = redir->next;
                }
		int spawn_ret;
		if (mystrcmp(cmd->argv[0], "sh.b") == 0 ||
		    mystrcmp(cmd->argv[0], "sh") == 0 ||
		    mystrcmp(cmd->argv[0], "/sh.b") == 0 ||
		    mystrcmp(cmd->argv[0], "/sh") == 0) {
            char *spawn_argv[MAX_CMD_ARGS + MAX_SHELL_VARS + 1]; // Max possible size
            int spawn_argc = 0;
            // 1. Copy command and its arguments
            for (int i = 0; i < cmd->argc; ++i) {
                spawn_argv[spawn_argc++] = cmd->argv[i];
            }
            // 2. Append exported environment variables
            char env_str_pool[MAX_SHELL_VARS][MAX_VAR_NAME_LEN + MAX_VAR_VALUE_LEN + 2]; // Pool for "NAME=VALUE" strings
            int env_str_idx = 0;

            for (int i = 0; i < MAX_SHELL_VARS; ++i) {
                if (shell_vars[i].is_set && shell_vars[i].is_exported) {
                    if (spawn_argc < (MAX_CMD_ARGS + MAX_SHELL_VARS) && env_str_idx < MAX_SHELL_VARS) {
                        char *current_env_str = env_str_pool[env_str_idx++];
			if (shell_vars[i].is_readonly) {mystrcat(current_env_str, "1");	}
			else {mystrcat(current_env_str, "0");}
			mystrcat(current_env_str, shell_vars[i].name);
			mystrcat(current_env_str, "=");
			mystrcat(current_env_str, shell_vars[i].value);
                        spawn_argv[spawn_argc++] = current_env_str;
                    } else { /* too many args or env vars, handle error */ break; }
                }
            }
            spawn_argv[spawn_argc] = NULL; // Null-terminate argv for spawn
			//printf("create a child shell\n");
			int i;
			for (i = 0; i < spawn_argc; i++) {
				//printf("%s\n", spawn_argv[i]);
			}
			spawn_ret = spawn(cmd->argv[0], spawn_argv);
		} else {
               		spawn_ret = spawn(cmd->argv[0], (char **)cmd->argv); 
		}
                if (spawn_ret < 0) {
                    // Error message printed by spawn or child itself if command not found by spawn
                    printf("sh: failed to spawn '%s' (err %d)\n", cmd->argv[0], spawn_ret);
                }
		wait(spawn_ret);
                exit(); 
            } else { // Parent process
                wait(child_pid); 
                // After child exits, its stdout should have been flushed by its own exit sequence
                // or by kernel if it's a direct syscall write.
                // No explicit fflush needed here for child's output by parent.
            }
            break;
        }

        case NODE_PIPELINE: {
            if (pipe(pipe_fds) < 0) {
                user_panic("pipe creation failed");
            }

            int pid1 = fork();
            if (pid1 < 0) user_panic("fork for pipe left failed");

            if (pid1 == 0) { 
                close(pipe_fds[0]); 
                dup(pipe_fds[1], 1);  
                close(pipe_fds[1]); 
                execute_ast(node->data.binary_op.left);
                exit(); 
            }

            int pid2 = fork();
            if (pid2 < 0) {
                 user_panic("fork for pipe right failed");
            }
            if (pid2 == 0) {
                close(pipe_fds[1]);
                dup(pipe_fds[0], 0);
                close(pipe_fds[0]);
                execute_ast(node->data.binary_op.right);
                exit();
            }
            
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            wait(pid1);
            wait(pid2);
            break;
        }

        case NODE_LIST_SEMI:
            execute_ast(node->data.binary_op.left);
            if (node->data.binary_op.right) { 
                execute_ast(node->data.binary_op.right);
            }
            break;
        
        case NODE_LIST_AMP: 
            child_pid = fork();
            if (child_pid < 0) user_panic("fork for & failed");
            if (child_pid == 0) {
                execute_ast(node->data.binary_op.left);
                exit();
            }
            if (node->data.binary_op.right) { 
                execute_ast(node->data.binary_op.right);
            }
            break;

        case NODE_AND: 
            // TODO: Proper exit status handling needed
            execute_ast(node->data.binary_op.left);
            // For now, simplified: always execute right if it exists
            if (node->data.binary_op.right) {
                 execute_ast(node->data.binary_op.right);
            }
            break;

        case NODE_OR: 
            // TODO: Proper exit status handling needed
            execute_ast(node->data.binary_op.left);
            // For now, simplified: always execute right if it exists
            if (node->data.binary_op.right) {
                execute_ast(node->data.binary_op.right);
            }
            break;
        
        default:
            user_panic("Unknown AST node type: %d", node->type);
    }
}


void readline(char *buf, u_int n, int interactive) {
	int r;
	u_int i = 0; 
	char c;

	for (i = 0; i < n - 1; /* i is managed inside */ ) { 
		if ((r = read(0, &c, 1)) != 1) {
			buf[i] = 0; 
			if (interactive && r==0) { /* Ctrl+D on empty line */ }
			else if (r < 0 && interactive) { debugf("readline: read error: %d\n", r); }
			// Shell exit on read error or non-interactive EOF
			if (r < 0 || (!interactive && r==0)) {
				if (interactive && r==0) { printf("exit\n"); } // Make it explicit for Ctrl+D
				exit();
			}
			return; 
		}

		if (c == '\b' || c == 0x7f) { 
			if (i > 0) {
				i--; 
			}
		} else if (c == '\r' || c == '\n') {
			if (interactive) {
                printf("\n"); 
            }
			buf[i] = 0;
			return;
		} else {
			buf[i] = c;
            i++; 
		}
	}
    // Buffer full
	if (interactive) printf("\n"); 
	debugf("readline: line too long\n");
	buf[n-1] = 0; 
	
	char discard_char;
	while ((r = read(0, &discard_char, 1)) == 1 && discard_char != '\r' && discard_char != '\n');
}


// --- Main Shell Loop ---
char input_buf[MAX_INPUT_BUF];

void usage(void) {
    printf("usage: sh [-ix] [script-file]\n");
    exit(); 
}


int main(int argc, char **argv) {
    init_shell_vars();
    int interactive = iscons(0);
    int echocmds = 0; 
    int initial_arg_idx = 0; // For parsing ARGBEGIN

    printf("\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");
    printf("::                                                         ::\n");
    printf("::                 MOS Shell (New Arch)                    ::\n");
    printf("::                                                         ::\n");
    printf(":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

    ARGBEGIN {
    case 'i':
        interactive = 1;
        break;
    case 'x':
        echocmds = 1;
        break;
    default:
        usage();
    }
    ARGEND

    initial_arg_idx = 0; // Update based on how many options ARGBEGIN consumed

    // Import environment variables passed from parent shell (if any)
    // These are after shell options and before a script file argument
    for (int i = initial_arg_idx; i < argc; ++i) {
        char *arg = argv[i];
        char *eq_ptr = strchr(arg, '=');
	//printf("child shell receive: %s\n", argv[i]);
        if (eq_ptr && (eq_ptr != arg)) { // Has '=' and it's not the first char
            // This is likely an environment variable from parent
            // The next argument would be the script file, if present.
            // This logic needs to be robust if a script file can also have '=' in its name.
            // For now, assume "NAME=VAL" before script file are env vars.
            
            char name[MAX_VAR_NAME_LEN + 1];
            char value_buf[MAX_VAR_VALUE_LEN + 1];
	    int is_readonly = 0;
	    is_readonly = arg[0] == '1' ? 1 : 0;
	    arg++;
            int name_len = eq_ptr - arg;
            if (name_len <= MAX_VAR_NAME_LEN) {
                mystrncpy(name, arg, name_len);
                name[name_len] = '\0';
		//printf("add declaration: %s\n", name);
                if (mystrlen(eq_ptr + 1) <= MAX_VAR_VALUE_LEN) {
                    mystrcpy(value_buf, eq_ptr + 1);
                    // Imported vars are exported, not readonly by default.
                    set_variable(name, value_buf, 1, is_readonly, 0); // update_flags_if_exists = 0 (new var)
                }
            }
            initial_arg_idx++; // Consumed this argument
        } else {
            // This must be the script file argument
            break;
        }
    }

    if (argc > initial_arg_idx) { 
        close(0);
        int r_open = open(argv[initial_arg_idx], O_RDONLY);
        if (r_open < 0) {
            user_panic("open %s: %d", argv[0], r_open);
        }
        if (r_open != 0) { 
            dup(r_open, 0);
            close(r_open);
        }
        interactive = 0; 
    }

    for (;;) {
        reset_allocators(); 
        memset(input_buf, 0, sizeof(input_buf)); 

        if (interactive) {
            printf("\n$ ");
            // Explicitly flush prompt for interactive mode
        }
        
        readline(input_buf, sizeof input_buf, interactive);

        if (input_buf[0] == '\0') { // Empty line or EOF from readline
            if (interactive) {
                // Check if it was a real EOF (Ctrl+D on its own line)
                // Readline's current logic might return empty buffer for Ctrl+D.
                // A more robust EOF check might be needed if read() returns 0 for EOF.
                // For now, assume empty buffer on interactive prompt means try again or was EOF.
                // If readline exited due to Ctrl+D, shell should have exited.
                // If readline returned because user just pressed enter, input_buf[0] is 0.
                int eof_check_r = read(0, &input_buf[0], 0); // Non-blocking check essentially
                 if (eof_check_r < 0) { // MOS specific EOF check
                      exit();
                 } else if (eof_check_r == 0 && !interactive) { // File EOF
                     exit();
                 }
                 // If it was just an empty line, loop again.
                 if (input_buf[0] == '\0' && interactive) continue;


            } else { // Non-interactive: empty line means EOF or end of script processing
                 exit();
            }
        }

        if (echocmds && input_buf[0] != '\0') {
            printf("# %s\n", input_buf);
        }
        
        const char* temp_scan = input_buf;
        while (*temp_scan && strchr(" \t\r\n", *temp_scan)) temp_scan++;
        if (*temp_scan == '#' || *temp_scan == '\0') {
            continue; 
        }

        tokenizer_init(input_buf); // Initialize tokenizer for *each line*
        ASTNode *ast = parse_line();

        if (ast) {
            execute_ast(ast);
            // AST resources are from static pools, reset by reset_allocators() next iteration
        } else {
            // Only print syntax error if it wasn't just an empty/comment line
            if(input_buf[0] != '\0' && input_buf[0] != '#') {
                 // Parser might have already printed a more specific error
                 if (current_token.type != TOKEN_EOF && current_token.type != TOKEN_EOL && current_token.type != TOKEN_ERROR) {
                    printf("sh: syntax error near token '%s'\n", current_token.value);
                 }
            }
        }
        if (interactive) {
        }
    }
    return 0; 
}

// mystrncpy and mystrncmp remain unchanged from your provided version.
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

void init_shell_vars() {
    for (int i = 0; i < MAX_SHELL_VARS; ++i) {
        shell_vars[i].is_set = 0;
        shell_vars[i].name[0] = '\0';
        shell_vars[i].value[0] = '\0';
        shell_vars[i].is_exported = 0;
        shell_vars[i].is_readonly = 0;
    }
    num_set_vars = 0;
}

ShellVar* find_variable(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < MAX_SHELL_VARS; ++i) {
        if (shell_vars[i].is_set && mystrcmp(shell_vars[i].name, name) == 0) {
            return &shell_vars[i];
        }
    }
    return NULL;
}

ShellVar* find_free_slot() {
    for (int i = 0; i < MAX_SHELL_VARS; ++i) {
        if (!shell_vars[i].is_set) {
            return &shell_vars[i];
        }
    }
    return NULL; // No free slot
}

int set_variable(const char *name, const char *value, int export_flag, int readonly_flag, int update_flags_if_exists) {
    if (mystrlen(name) > MAX_VAR_NAME_LEN) {
        //printf("sh: variable name too long: %s\n", name);
        return -1;
    }
    if (value && mystrlen(value) > MAX_VAR_VALUE_LEN) {
        //printf("sh: variable value too long for %s\n", name);
        return -1;
    }

    ShellVar *var = find_variable(name);
    if (var) { // Variable exists
        if (var->is_readonly) {
            //printf("sh: %s: readonly variable\n", name);
            return -1; // Cannot modify readonly variable's value or non-readonly flags
        }
        mystrcpy(var->value, value ? value : "");
        if (update_flags_if_exists) {
            var->is_exported = export_flag;
            // Only allow setting readonly, not clearing it if already readonly (though caught above)
            if (readonly_flag) var->is_readonly = 1;
        }
    } else { // New variable
        var = find_free_slot();
        if (!var) {
            //printf("sh: maximum number of variables reached\n");
            return -1;
        }
        mystrcpy(var->name, name);
        mystrcpy(var->value, value ? value : "");
        var->is_exported = export_flag;
        var->is_readonly = readonly_flag;
        var->is_set = 1;
        num_set_vars++;
    }
    return 0;
}

int unset_variable(const char *name) {
    ShellVar *var = find_variable(name);
    if (!var) {
        // Bash typically doesn't error here, but for MOS, let's be stricter.
        //printf("sh: %s: not found\n", name);
        return -1;
    }
    if (var->is_readonly) {
        //printf("sh: %s: readonly variable\n", name);
        return -1;
    }
    var->is_set = 0;
    var->name[0] = '\0'; // Clear name for easier free slot finding
    num_set_vars--;
    return 0;
}

void print_all_variables() {
    for (int i = 0; i < MAX_SHELL_VARS; ++i) {
        if (shell_vars[i].is_set) {
            // Format: <var>=<val>
            // Optionally, could add prefixes like 'export ' or 'readonly '
            printf("%s%s%s=%s\n",
                   shell_vars[i].is_exported ? "" : "", // For more bash-like output, if desired
                   shell_vars[i].is_readonly ? "" : "",
                   shell_vars[i].name,
                   shell_vars[i].value);
        }
    }
}

char* get_variable_value(const char *name) {
    ShellVar *var = find_variable(name);
    if (var && var->is_set) {
        return var->value;
    }
    return NULL; // Or "" for empty string if not found
}

char *mystrchr(const char *str, char c) {
    // 遍历字符串直到遇到 '\0'
    while (*str) {
        if (*str == (char)c) {
            return (char *)str; // 找到字符，返回指针
        }
        str++;
    }
    // 检查是否查找的是 '\0'
    if (c == '\0') {
        return (char *)str;
    }
    return NULL; // 未找到字符
}

