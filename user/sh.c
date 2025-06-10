#include <args.h>
#include <lib.h>
#include <fs.h>     // Added for O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC, O_APPEND
//#include <stdlib.h> // Commented out to avoid exit conflict initially

// --- Configuration ---
#define MAX_INPUT_BUF 1024
#define MAX_TOKEN_LEN 1024
#define MAX_CMD_ARGS 128

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
char strdup_pool[100][1000] = {0}; // Renamed for clarity
int strdup_pool_index = 0;

ASTNode astnode_pool[100] = {0}; // Reduced size for testing, adjust as needed
int astnode_pool_index = 0;

RedirNode redirnode_pool[100] = {0}; // Reduced size
int redirnode_pool_index = 0;

void reset_allocators() {
    strdup_pool_index = 0;
    astnode_pool_index = 0;
    redirnode_pool_index = 0;
    // Optionally, could also memset the pools to 0 if needed for strict hygiene,
    // but for simple sequential use, just resetting indices is often enough.
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
    memcpy(new_s, s, len); // Use memcpy from lib.h
    return new_s;
}

ASTNode *alloc_ast_node(ASTNodeType type) {
    if (astnode_pool_index >= 100) {
        user_panic("astnode_pool out of space");
    }
    ASTNode *node = &astnode_pool[astnode_pool_index++];
    memset(node, 0, sizeof(ASTNode)); // Clear the node
    node->type = type;
    return node;
}

RedirNode *alloc_redir_node() {
    if (redirnode_pool_index >= 100) {
        user_panic("redirnode_pool out of space");
    }
    RedirNode *node = &redirnode_pool[redirnode_pool_index++];
    memset(node, 0, sizeof(RedirNode)); // Clear the node
    return node;
}


// --- Tokenizer Globals ---
static const char *current_pos; 
static Token current_token;
static Token peeked_token;
static int has_peeked_token;


// --- Tokenizer Implementation (No changes from previous version) ---
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
        if (i == 0) { // Should only happen if initial current_pos was already pointing to a delimiter or EOF
             if (*current_pos == '\0') token.type = TOKEN_EOF;
             else token.type = TOKEN_ERROR; // Or some other non-word token was expected by caller
        }
    }
    return token;
}

void tokenizer_init(const char *input) { 
    current_pos = input;
    has_peeked_token = 0;
    current_token = get_next_raw_token();
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
        peeked_token = get_next_raw_token(); // This might advance current_pos if called alone
        has_peeked_token = 1;
    }
    return peeked_token; // Return the peeked one
}


// --- Parser (Recursive Descent) ---
ASTNode *parse_and_or(void);
ASTNode *parse_pipeline(void);
ASTNode *parse_command(void);

ASTNode *parse_line() {
    // If the first token is EOF, it's an empty line effectively
    if (current_token.type == TOKEN_EOF || current_token.type == TOKEN_EOL) {
        return NULL;
    }
    return parse_list();
}

ASTNode *parse_list() {
    ASTNode *node = parse_and_or();
    if (!node) { // Handles empty input or parse error from and_or
        return NULL;
    }

    while (current_token.type == TOKEN_SEMI || current_token.type == TOKEN_AMP) {
        TokenType op_type = current_token.type;
        consume_token();

        if (current_token.type == TOKEN_EOF || current_token.type == TOKEN_EOL) { // Trailing ; or &
            ASTNode *new_list_node = alloc_ast_node(op_type == TOKEN_SEMI ? NODE_LIST_SEMI : NODE_LIST_AMP);
            new_list_node->data.binary_op.left = node;
            new_list_node->data.binary_op.right = NULL;
            node = new_list_node;
            break; 
        }

        ASTNode *right_node = parse_and_or();
        if (!right_node) {
            debugf("Syntax error after '%s'\n", op_type == TOKEN_SEMI ? ";" : "&");
            // free_ast_resources(); // Not freeing partial tree, rely on main loop reset
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
            // free_ast_resources();
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
            // free_ast_resources();
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
    // Check if the current token can start a command (WORD or redirection)
    if (current_token.type != TOKEN_WORD &&
        current_token.type != TOKEN_REDIR_IN &&
        current_token.type != TOKEN_REDIR_OUT &&
        current_token.type != TOKEN_REDIR_APP) {
        // If it's EOF or EOL, it's not a command.
        if (current_token.type == TOKEN_EOF || current_token.type == TOKEN_EOL) return NULL;
        // If it's another operator, it's a syntax error (e.g. "|| ls" or "| |")
        // This should be caught by higher-level parsers.
        // However, if parse_command is called directly and sees an operator, it's an error here.
        // debugf("Syntax error: Expected command or redirection, got '%s'\n", current_token.value);
        return NULL; // Indicates no command could be formed
    }

    ASTNode *cmd_node_ast = alloc_ast_node(NODE_COMMAND);
    CMDNodeData *cmd_data = &cmd_node_ast->data.command;
    // No memset here, alloc_ast_node does it.
    RedirNode **next_redir_ptr = &cmd_data->redirects;

    // Collect all redirections and words
    while (current_token.type == TOKEN_WORD ||
           current_token.type == TOKEN_REDIR_IN ||
           current_token.type == TOKEN_REDIR_OUT ||
           current_token.type == TOKEN_REDIR_APP) {

        if (current_token.type == TOKEN_WORD) {
            if (cmd_data->argc < MAX_CMD_ARGS - 1) {
                cmd_data->argv[cmd_data->argc++] = user_strdup(current_token.value);
            } else {
                debugf("Too many arguments for command\n");
                // free_ast_resources(); // Rely on main loop reset
                return NULL; // Error
            }
            consume_token();
        } else { // Redirection
            TokenType redir_op_type = current_token.type;
            consume_token(); 

            if (current_token.type != TOKEN_WORD) {
                debugf("Syntax error: Redirection operator not followed by filename\n");
                // free_ast_resources();
                return NULL; // Error
            }

            RedirNode *redir_node = alloc_redir_node();
            if (redir_op_type == TOKEN_REDIR_IN) redir_node->type = REDIR_TYPE_IN;
            else if (redir_op_type == TOKEN_REDIR_OUT) redir_node->type = REDIR_TYPE_OUT;
            else if (redir_op_type == TOKEN_REDIR_APP) redir_node->type = REDIR_TYPE_APP;
            // No need for else panic, types are checked

            redir_node->filename = user_strdup(current_token.value);
            consume_token(); 

            *next_redir_ptr = redir_node;
            next_redir_ptr = &redir_node->next;
        }
    }
    cmd_data->argv[cmd_data->argc] = NULL; 

    // If nothing was parsed (no words, no redirects), it's not a valid command node.
    if (cmd_data->argc == 0 && cmd_data->redirects == NULL) {
        // alloc_ast_node makes a node, but it's empty. If we reset allocators, this is fine.
        // No need to explicitly free here if allocators are reset per command line.
        return NULL;
    }
    return cmd_node_ast;
}


// --- AST Executor ---
void execute_ast(ASTNode *node) {
    if (!node) {
        return;
    }

    int child_pid;
    int pipe_fds[2];
    // Unused variables removed

    switch (node->type) {
        case NODE_COMMAND: {
            CMDNodeData *cmd = &node->data.command;
            if (cmd->argc == 0 && cmd->redirects == NULL) {
                return;
            }
            if (cmd->argc == 0) { // Only redirections, no command name
                // MOS spawn requires a command. POSIX shell might handle this differently.
                // For now, if no command name, we can't spawn.
                // We could fork and apply redirections, then exit, but that's for later.
                debugf("sh: missing command for redirection\n");
                return;
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
                        // O_APPEND is assumed defined in fs.h now
                        open_flags = O_WRONLY | O_CREAT | O_APPEND; 
                        target_fd_std = 1; 
                    }

                    int opened_fd = open(redir->filename, open_flags);
                    if (opened_fd < 0) {
                        debugf("sh: cannot open %s\n", redir->filename);
                        exit(); 
                    }
                    dup(opened_fd, target_fd_std);
                    close(opened_fd);
                    redir = redir->next;
                }

                int spawn_ret = spawn(cmd->argv[0], (char **)cmd->argv); 
                if (spawn_ret < 0) {
                    debugf("sh: failed to spawn '%s' (err %d)\n", cmd->argv[0], spawn_ret);
                }
                exit(); 
            } else { // Parent process
                wait(child_pid); 
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

            // Fork second child for the right side of the pipe
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
            
            // Parent closes both ends of the pipe
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
            // Parent does not wait
            if (node->data.binary_op.right) { 
                execute_ast(node->data.binary_op.right);
            }
            break;

        case NODE_AND: 
            // TODO: Proper exit status handling needed
            // For now, acts like semicolon
            execute_ast(node->data.binary_op.left);
            // if (left_succeeded)
            if (node->data.binary_op.right) { // Check if right node exists
                 execute_ast(node->data.binary_op.right);
            }
            break;

        case NODE_OR: 
            // TODO: Proper exit status handling needed
            // For now, acts like semicolon
            execute_ast(node->data.binary_op.left);
            // if (left_failed)
            if (node->data.binary_op.right) { // Check if right node exists
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

	for (i = 0; i < n - 1; /* i incremented inside or reset */ ) { // Leave space for null terminator
		if ((r = read(0, &c, 1)) != 1) { // Read one character
			if (r < 0 && interactive) { 
				debugf("readline: read error: %d\n", r);
			}
			buf[i] = 0; 
			// On EOF (Ctrl+D for interactive, or end of script) or error
			if (interactive && r == 0) { 
				// For interactive Ctrl+D, main loop will handle exit if buf is empty
			} else if (!interactive && r <= 0) {
				// For script EOF or error, main loop might also break, or shell exits here
			}
			// For MOS, exit() is from lib.h and usually takes no arguments.
			// If we want to signal an error state for the shell, we might exit(1).
			// For now, let readline return and let main decide based on buf[0].
			// If it's a real error or script EOF, the shell should likely terminate.
			if (r < 0 || (!interactive && r==0)) exit(); 
			return; 
		}

		if (c == '\b' || c == 0x7f) { // Backspace or DEL
			if (i > 0) {
				// Terminal handles visual backspace. We just update our buffer.
				i--; 
			}
            // else: i is 0, nothing to backspace in buffer
		} else if (c == '\r' || c == '\n') {
			if (interactive) {
                // If terminal is in raw mode, we might need to print \r\n ourselves.
                // Assuming canonical mode where terminal handles CR to CRLF or just LF.
                // For simplicity, MOS shell often just prints \n.
                printf("\n"); 
            }
			buf[i] = 0;
			return;
		} else {
			// NO explicit echo: if (interactive) printf("%c", c);
			buf[i] = c;
            i++; // Increment index only for normal characters
		}
	}
    // Buffer full
	if (interactive) printf("\n"); 
	debugf("readline: line too long\n");
	buf[n-1] = 0; 
	
	char discard_char;
	while ((r = read(0, &discard_char, 1)) == 1 && discard_char != '\r' && discard_char != '\n') {
		; // Discard rest of the line
	}
    // If the line was too long and we discarded, and it ended with newline,
    // ensure a newline is printed if interactive (already handled by buffer full case)
    // if (interactive && (discard_char == '\r' || discard_char == '\n')) {
    // printf("\n");
    // }
}


// --- Main Shell Loop ---
char input_buf[MAX_INPUT_BUF];

void usage(void) {
    printf("usage: sh [-ix] [script-file]\n");
    exit(); 
}


int main(int argc, char **argv) {
    int interactive = iscons(0);
    int echocmds = 0; 

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

    if (argc > 1) { 
        close(0);
        int r_open = open(argv[0], O_RDONLY);
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
        if (interactive) {
            printf("\n$ ");
        }
        
        reset_allocators(); 
        memset(input_buf, 0, sizeof(input_buf)); 
        readline(input_buf, sizeof input_buf, interactive);

        // Check for EOF (Ctrl+D in interactive mode)
        if (input_buf[0] == '\0') {
            if (interactive) {
                // This condition checks if readline returned an empty buffer,
                // which can happen if read(0, &c, 1) returned 0 (EOF).
                // A more robust way is if readline itself signals EOF.
                int eof_check_r = read(0, &input_buf[0], 0); // Check fd 0 status
                if (eof_check_r < 0) { // Assuming -E_EOF
                     printf("exit\n");
                     exit();
                } else if (eof_check_r == 0) { // Typically means EOF on a regular file
                     printf("exit\n");
                     exit();
                }
                // If still empty after these checks, it might be just an empty line.
            } else { // Non-interactive (script)
                 // End of script
                 exit();
            }
        }


        if (echocmds && input_buf[0] != '\0') {
            printf("# %s\n", input_buf);
        }
        
        const char* temp_scan = input_buf;
        while (*temp_scan && strchr(" \t\r\n", *temp_scan)) temp_scan++;
        if (*temp_scan == '#' || *temp_scan == '\0') {
            if (input_buf[0] == '\0' && interactive) { /* Already handled EOF above */ }
            else { continue; } // Skip comment or truly empty lines
        }

        tokenizer_init(input_buf);
        ASTNode *ast = parse_line();

        if (ast) {
            execute_ast(ast);
        } else {
            if(current_token.type != TOKEN_EOF && current_token.type != TOKEN_EOL && current_token.type != TOKEN_ERROR && input_buf[0] != '\0'){
                 debugf("sh: syntax error or no command entered near '%s'\n", current_token.value);
            }
        }
    }
    return 0; // Should not be reached in normal operation
}

// mystrncpy and mystrncmp remain unchanged from your provided version.
// ... [mystrncpy and mystrncmp definitions] ...
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
