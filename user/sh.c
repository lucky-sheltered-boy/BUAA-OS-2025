#include <args.h>
#include <lib.h>
#include <fs.h>     // Added for O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC, O_APPEND
//#include <stdlib.h>

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
ASTNode *parse_list(void); // Forward declaration
void readline(char *buf, u_int n, int interactive); // Forward declaration

// --- Placeholder for Malloc/Free ---

char strdup[100][1000] = {0};
int strdup_index = 0;

char *user_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    if (strdup_index >= 100) {
	user_panic("strdup out of number limit");
    }
    char *new_s = strdup[strdup_index++];
    if (new_s) {
        memcpy(new_s, s, len);
    } else {
        debugf("user_strdup: user_malloc failed\n");
    }
    return new_s;
}


// --- Tokenizer Globals ---
static const char *current_pos; // Current position in the input string
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
                 current_pos++; // Consume the newline as well
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
               !strchr("|;&<>#", *current_pos) && // Include '#' here to stop word at comment
               i < MAX_TOKEN_LEN - 1) {
            // Check for multi-char ops that might start with a char also in SYMBOLS_SINGLE
             if (mystrncmp(current_pos, "&&", 2) == 0 || mystrncmp(current_pos, "||", 2) == 0 || mystrncmp(current_pos, ">>", 2) == 0) {
                break;
            }
            token.value[i++] = *current_pos++;
        }
        token.value[i] = '\0';
        if (i == 0) {
             token.type = TOKEN_EOF; // Or error if not truly EOF
        }
    }
    return token;
}

void tokenizer_init(const char *input) { // Made input const
    current_pos = input;
    has_peeked_token = 0;
    current_token = get_next_raw_token();
}

Token consume_token() {
    Token old_current = current_token;
    if (current_token.type == TOKEN_EOF) return old_current; // Do not advance past EOF

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

ASTNode astnode[1000];
int astnode_index = 0;

// --- AST Node Allocation ---
ASTNode *alloc_ast_node(ASTNodeType type) {
    if (astnode_index >= 1000) {
	user_panic("astnode out of number limit");
    }
    ASTNode *node = &astnode[astnode_index++];
    if (!node) {
        user_panic("alloc_ast_node: out of memory");
    }
    memset(node, 0, sizeof(ASTNode));
    node->type = type;
    return node;
}

RedirNode redirnode[1000];
int redirnode_index = 0;

RedirNode *alloc_redir_node() {
    if (redirnode_index >= 1000) {
	user_panic("redirnode out of number limit");
    }
    RedirNode *node = &redirnode[redirnode_index++];
    if (!node) {
        user_panic("alloc_redir_node: out of memory");
    }
    memset(node, 0, sizeof(RedirNode));
    return node;
}


// --- Parser (Recursive Descent) ---
// Forward declarations for mutual recursion
ASTNode *parse_and_or(void);
ASTNode *parse_pipeline(void);
ASTNode *parse_command(void);

// line ::= list
ASTNode *parse_line() {
    return parse_list();
}

// list ::= and_or ( ( ";" | "&" ) and_or )*
ASTNode *parse_list() {
    ASTNode *node = parse_and_or();
    // If parse_and_or returns NULL (e.g., empty input or error), node will be NULL.
    // If it's an empty input, we should return NULL to signify no command.
    if (!node && (current_token.type == TOKEN_EOF || current_token.type == TOKEN_EOL)) {
        return NULL;
    }
    // If it was an error, node is NULL, and we might want to propagate that.
    // For now, let's assume parse_and_or handles its own errors and returns NULL on error.
    if (!node) return NULL;


    while (current_token.type == TOKEN_SEMI || current_token.type == TOKEN_AMP) {
        TokenType op_type = current_token.type;
        consume_token(); 

        // Handle cases like "cmd ;" or "cmd &" followed by EOL/EOF
        if (current_token.type == TOKEN_EOF || current_token.type == TOKEN_EOL) {
            ASTNode *new_list_node = alloc_ast_node(op_type == TOKEN_SEMI ? NODE_LIST_SEMI : NODE_LIST_AMP);
            new_list_node->data.binary_op.left = node;
            new_list_node->data.binary_op.right = NULL; // No command on the right
            node = new_list_node;
            break; // End of list
        }

        ASTNode *right_node = parse_and_or();
        if (!right_node) { // Error in parsing right side or unexpected end
             if(current_token.type != TOKEN_EOF && current_token.type != TOKEN_EOL) {
                debugf("Syntax error after '%s'\n", op_type == TOKEN_SEMI ? ";" : "&");
             }
            return NULL;
        }

        ASTNode *new_list_node = alloc_ast_node(op_type == TOKEN_SEMI ? NODE_LIST_SEMI : NODE_LIST_AMP);
        new_list_node->data.binary_op.left = node;
        new_list_node->data.binary_op.right = right_node;
        node = new_list_node;
    }
    return node;
}

// and_or ::= pipeline ( ( "&&" | "||" ) pipeline )*
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

// pipeline ::= command ( "|" command )*
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

// command ::= WORD ( WORD | redirect )*
ASTNode *parse_command() {
     // A command must start with a WORD, or can be just redirections followed by a WORD,
     // or just redirections. The EBNF implies WORD must come first if no redirections.
     // Let's allow optional leading redirections before the first WORD.
    int first_word_found = 0;
    ASTNode *cmd_node_ast = alloc_ast_node(NODE_COMMAND);
    CMDNodeData *cmd_data = &cmd_node_ast->data.command;
    cmd_data->argc = 0;
    cmd_data->redirects = NULL;
    RedirNode **next_redir_ptr = &cmd_data->redirects;

    while (1) {
        if (current_token.type == TOKEN_WORD) {
            first_word_found = 1;
            if (cmd_data->argc < MAX_CMD_ARGS -1) {
                cmd_data->argv[cmd_data->argc++] = user_strdup(current_token.value);
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
            else { user_panic("Unknown redir type");}


            redir_node->filename = user_strdup(current_token.value);
            consume_token(); 

            *next_redir_ptr = redir_node;
            next_redir_ptr = &redir_node->next;
        } else {
            break; // Not a word or redirection, end of simple command
        }
    }
    cmd_data->argv[cmd_data->argc] = NULL;

    if (cmd_data->argc == 0 && cmd_data->redirects == NULL) {
         return NULL; // No command parsed (e.g. empty input or just operators)
    }
    // If only redirections but no command name, this is valid in some shells (e.g. `> file`)
    // For MOS, spawn needs a command name.
    if (cmd_data->argc == 0 && cmd_data->redirects != NULL) {
        // Allow this for now, execute_ast will handle if it's runnable
        // or we can choose to make it a syntax error if no command name.
        // For simplicity, let's say a command name is required for execution.
        // However, a command can consist of only redirections (e.g., '>out').
        // The EBNF `command ::= WORD ( WORD | redirect )*` implies the first element of a command part
        // must be a WORD unless the command *only* consists of redirections handled differently.
        // Let's stick to the EBNF meaning for now that WORD is expected at the start of the "command" part.
        // A pure redirection sequence is not what our `parse_command` aims to parse as a runnable command.
        // This logic needs refinement if `>out` style commands are to be supported without a preceding WORD.
        // For now, if `argc == 0`, `spawn` will fail.
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

    switch (node->type) {
        case NODE_COMMAND: {
            CMDNodeData *cmd = &node->data.command;
            if (cmd->argc == 0 && cmd->redirects == NULL) { // Should be caught by parser returning NULL
                return;
            }
            // If only redirections, and no command, what to do?
            // Standard shells might apply redirections to the shell itself or a null command.
            // For us, `spawn` needs a command name.
            if (cmd->argc == 0) {
                // Apply redirections, but there's no command to run.
                // This scenario needs careful thought. For now, do nothing if no command.
                // Or, if we have redirections, fork a child that does nothing but apply them.
                // debugf("Command node with no arguments to execute.\n");
                // TODO: Handle redirections-only commands if necessary.
                // For now, if argc is 0, spawn will fail.
                return;
            }


            // Fork for command execution to isolate redirections and environment.
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
                        target_fd_std = 0; // stdin
                    } else if (redir->type == REDIR_TYPE_OUT) {
                        open_flags = O_WRONLY | O_CREAT | O_TRUNC;
                        target_fd_std = 1; // stdout
                    } else if (redir->type == REDIR_TYPE_APP) {
                        open_flags = O_WRONLY | O_CREAT;
                        target_fd_std = 1; // stdout
                    }

                    int opened_fd = open(redir->filename, open_flags);
                    if (opened_fd < 0) {
                        debugf("sh: cannot open %s\n", redir->filename);
                        exit(); // Child exits on redirection error
                    }
                    dup(opened_fd, target_fd_std);
                    close(opened_fd);
                    redir = redir->next;
                }

                int spawn_ret = spawn(cmd->argv[0], (char **)cmd->argv); // Cast for spawn
                if (spawn_ret < 0) {
                    debugf("sh: command not found or failed to spawn: %s (err %d)\n", cmd->argv[0], spawn_ret);
                }
                exit(); // Child exits after spawn attempt
            } else { // Parent process
                wait(child_pid); // Parent waits for the command child
            }
            break;
        }

        case NODE_PIPELINE: {
            if (pipe(pipe_fds) < 0) {
                user_panic("pipe creation failed");
            }

            int pid1 = fork();
            if (pid1 < 0) user_panic("fork for pipe left failed");

            if (pid1 == 0) { // Child 1 (left side of pipe)
                close(pipe_fds[0]); 
                dup(pipe_fds[1], 1);  
                close(pipe_fds[1]); 
                execute_ast(node->data.binary_op.left);
                exit(); 
            }

            int pid2 = fork();
            if (pid2 < 0) user_panic("fork for pipe right failed");

            if (pid2 == 0) { // Child 2 (right side of pipe)
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
                // Child runs in background, no wait from immediate parent shell loop
                execute_ast(node->data.binary_op.left);
                exit();
            }
            // Parent does not wait for node->data.binary_op.left
            if (node->data.binary_op.right) { // If there's "cmd1 & cmd2"
                execute_ast(node->data.binary_op.right);
            }
            break;

        case NODE_AND: // TODO: Needs proper exit status handling
            debugf("Warning: && execution is simplified, currently acts like ;\n");
            execute_ast(node->data.binary_op.left);
            // if (exit_status_of_left == 0)
            execute_ast(node->data.binary_op.right);
            break;

        case NODE_OR: // TODO: Needs proper exit status handling
            debugf("Warning: || execution is simplified, currently acts like ;\n");
            execute_ast(node->data.binary_op.left);
            // if (exit_status_of_left != 0)
            execute_ast(node->data.binary_op.right);
            break;
        
        default:
            user_panic("Unknown AST node type: %d", node->type);
    }
}



// --- Main Shell Loop ---
char input_buf[MAX_INPUT_BUF];

void usage(void) {
    printf("usage: sh [-ix] [script-file]\n");
    exit(); // Exit with error status
}

// readline is defined in the original sh.c, assuming it's available.
// If not, it needs to be copied or reimplemented.
// For now, I'll copy its signature here for clarity.
void readline(char *buf, u_int n, int interactive);


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
        usage(); 
    }

    for (;;) {
        if (interactive) {
            printf("\n$ ");
        }

        readline(input_buf, sizeof input_buf, interactive);

        if (input_buf[0] == '\0' && current_pos == input_buf) { // Truly empty line after readline processing
            continue;
        }
         // Check for EOF from readline if it indicates it (e.g., by returning a specific value or string content)
        // This simple readline doesn't explicitly return EOF for interactive sessions, Ctrl-D might map to 0.


        if (echocmds && input_buf[0] != '\0') { // Don't echo empty lines if # was the only content
            printf("# %s\n", input_buf);
        }
        
        // Skip pure comment lines after echocmds
        const char* temp_scan = input_buf;
        while (*temp_scan && strchr(" \t\r\n", *temp_scan)) temp_scan++;
        if (*temp_scan == '#' || *temp_scan == '\0') {
            continue;
        }


        tokenizer_init(input_buf);
        ASTNode *ast = parse_line();

        if (ast) {
            execute_ast(ast);
        } else {
            // Error already printed by parser, or it was an empty/comment line handled above
            // but if current_token is not EOF/EOL, it might be an unhandled syntax error start
            if(current_token.type != TOKEN_EOF && current_token.type != TOKEN_EOL && current_token.type != TOKEN_ERROR){
                 // This implies parser returned NULL for a non-empty, non-comment line without consuming all tokens,
                 // which usually means a syntax error it couldn't recover from at a higher level.
                 // debugf("sh: syntax error near token '%s'\n", current_token.value); // Parser should print specifics
            }
        }
    }
    return 0;
}


// Copied readline from original sh.c for completeness, assuming it's needed here
// and not in a separate user/lib/readline.c
void readline(char *buf, u_int n, int interactive) {
	int r;
	int i; // Declare i outside for loop
	for (i = 0; i < n; i++) { // Corrected loop condition to < n
		if ((r = read(0, buf + i, 1)) != 1) {
			if (r < 0) {
				debugf("read error: %d\n", r);
			}
			// On read error or EOF for script, exit the shell
			exit(); // Changed to exit with status
		}
		// Handle backspace
        // buf[i] will be the char read.
		if (buf[i] == '\b' || buf[i] == 0x7f) { // 0x7f is DEL
			if (i > 0) {
				printf("\b \b"); // Erase char on screen: back, space, back
				i -= 2; // Current char is backspace, previous char to be removed.
			} else {
				i = -1; // Effectively restarts loop for this char, or handles empty buffer backspace
			}
		} else if (buf[i] == '\r' || buf[i] == '\n') {
			buf[i] = 0; // Null terminate
        		if (interactive) printf("\n"); // Echo newline only if interactive
				return;
		} else {
            		if (interactive) printf("%c", buf[i]); // Echo character if interactive
        	}
	}
    // Buffer full
	debugf("line too long\n");
	buf[n-1] = 0; // Ensure null termination if buffer full
	// Discard rest of the line
	char discard_char;
	while ((r = read(0, &discard_char, 1)) == 1 && discard_char != '\r' && discard_char != '\n') {
		;
	}
    if (interactive && (discard_char == '\r' || discard_char == '\n')) {
        printf("\n");
    }
}


int mystrncpy(char* dest, const char* src, int count)
{
	char* start = dest; // 记录目标字符串起始位置
	while (count && (*dest++ = *src++)) // 拷贝字符串
	{
		count--;
	}
	if (count) // 当count大于src的长度时，将补充空字符
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

    while (i < n && s1[i] != '\0' && s2[i] != '\0') {
        if (s1[i] != s2[i]) {
            return (unsigned char)s1[i] - (unsigned char)s2[i];
        }
        i++;
    }

    if (i < n) {
        if (s1[i] != s2[i]) {
            return (unsigned char)s1[i] - (unsigned char)s2[i];
        }
    }

    return 0;
}
