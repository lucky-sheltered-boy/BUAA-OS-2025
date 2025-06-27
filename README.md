# OS lab6_shell 挑战性任务 实验报告
> 我实现挑战性任务的顺序并不是按照题目顺序，而是根据我认为的合理顺序来实现的，实验报告也将按照我实现指令的顺序来书写。

#### 重写 sh.c 架构

指导书中提出， Shell是一种命令解释器，对输入指令进行解析并执行。现有MOS实现的Shell较为简陋，如果在其基础上尝试实现挑战性任务内容可能复杂度较高，可以参考sh,bash等工业界shell实现原理进行重新实现，以下是一个可行的实现方案:

![[Pasted image 20250615101204.png]]

因此，我第一步先按照上述架构把 sh.c 重写了一遍，抛弃了原有课程组的代码，按照AST语法树来解析输入。代码如下（最后的完整版代码）：

```C
#include <args.h>
#include <lib.h>
#include <fs.h>

#define MAX_INPUT_BUF 1024
#define MAX_TOKEN_LEN 1024
#define MAX_CMD_ARGS 128
#define MAX_VAR_NAME_LEN 16
#define MAX_VAR_VALUE_LEN 16
#define MAX_SHELL_VARS 128
#define MAX_EXPANDED_STR_LEN (MAX_TOKEN_LEN * 2)
#define UP 'A'
#define DOWN 'B'
#define OTHER -1
#define HISTFILESIZE 20
#define HISTORY_FILE "/.mos_history"
#define WHITESPACE " \t\r\n"
#define MAX_CMD_SUBST_OUTPUT_LEN (MAX_INPUT_BUF * 2)
#define MAX_CMD_SUBST_BUFFERS 10

static char cmd_subst_output_pool[MAX_CMD_SUBST_BUFFERS][MAX_CMD_SUBST_OUTPUT_LEN];
static int cmd_subst_output_pool_idx = 0;

char* execute_command_substitution(const char* command_to_run, int parent_is_interactive);

static char history_lines[HISTFILESIZE][MAX_INPUT_BUF];
static int history_count = 0;
static int history_add_idx = 0;
static int history_latest_idx = -1;
static int history_current_nav_offset = 0;
static char current_typed_line[MAX_INPUT_BUF] = {0};

char expansion_buffer_pool[100][MAX_EXPANDED_STR_LEN];
int expansion_buffer_pool_index = 0;
char* expand_string_variables(char *input_str);
void *mymemmove(void *dest, const void *src, int n);
void write_history(char *buf);
void read_history(char ope[][600],int *sz);


typedef struct {
    char name[MAX_VAR_NAME_LEN + 1];
    char value[MAX_VAR_VALUE_LEN + 1];
    int is_exported;
    int is_readonly;
    int is_set;
} ShellVar;

static ShellVar shell_vars[MAX_SHELL_VARS];
static int num_set_vars = 0;

void init_shell_vars(void);
ShellVar* find_variable(const char *name);
int set_variable(const char *name, const char *value, int export_flag, int readonly_flag, int update_flags_if_exists);
int unset_variable(const char *name);
void print_all_variables(void);
char* get_variable_value(const char *name);

typedef struct ASTNode ASTNode;

typedef enum {
    NODE_ILLEGAL = 0,
    NODE_COMMAND,
    NODE_PIPELINE,
    NODE_LIST_SEMI,
    NODE_LIST_AMP,
    NODE_AND,
    NODE_OR,
} ASTNodeType;

typedef enum {
    TOKEN_ERROR = 0,
    TOKEN_EOF = 1,
    TOKEN_EOL = 2,
    TOKEN_WORD,
    TOKEN_PIPE,
    TOKEN_SEMI,
    TOKEN_AMP,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_REDIR_IN,
    TOKEN_REDIR_OUT,
    TOKEN_REDIR_APP,
} TokenType;

typedef struct {
    TokenType type;
    char value[MAX_TOKEN_LEN];
} Token;

typedef enum {
    REDIR_TYPE_IN,
    REDIR_TYPE_OUT,
    REDIR_TYPE_APP,
} RedirType;

typedef struct RedirNode {
    RedirType type;
    char *filename;
    struct RedirNode *next;
} RedirNode;

typedef struct {
    char *argv[MAX_CMD_ARGS];
    int argc;
    RedirNode *redirects;
} CMDNodeData;

typedef struct {
    ASTNode *left;
    ASTNode *right;
} BinaryOpNodeData;

struct ASTNode {
    ASTNodeType type;
    union {
        CMDNodeData command;
        BinaryOpNodeData binary_op;
    } data;
};

ASTNode *parse_list(void);
void readline(char *buf, u_int n, int interactive);
void free_ast_resources(void);

char strdup_pool[100][1000] = {0};
int strdup_pool_index = 0;

ASTNode astnode_pool[100] = {0};
int astnode_pool_index = 0;

RedirNode redirnode_pool[100] = {0};
int redirnode_pool_index = 0;

char* get_subst_output_buffer() {
    if (cmd_subst_output_pool_idx >= MAX_CMD_SUBST_BUFFERS) {
        printf("sh: too many command substitutions on one line\n");
        if (MAX_CMD_SUBST_BUFFERS > 0) {
            return cmd_subst_output_pool[MAX_CMD_SUBST_BUFFERS -1];
        }
        user_panic("cmd_subst_output_pool out of space and no fallback buffer");
    }
    memset(cmd_subst_output_pool[cmd_subst_output_pool_idx], 0, MAX_CMD_SUBST_OUTPUT_LEN);
    return cmd_subst_output_pool[cmd_subst_output_pool_idx++];
}

char* execute_command_substitution(const char* command_to_run, int parent_is_interactive) {
    int pipe_fds[2];
    int child_pid_for_sh_c;
    char *output_buffer = get_subst_output_buffer();
    output_buffer[0] = '\0';
    u_int output_len = 0;
    char read_char;
    int r;

    if (pipe(pipe_fds) < 0) {
        printf("sh: pipe failed for command substitution\n");
        return output_buffer;
    }

    child_pid_for_sh_c = fork();

    if (child_pid_for_sh_c < 0) {
        printf("sh: fork failed for command substitution\n");
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return output_buffer;
    }

    if (child_pid_for_sh_c == 0) {
        close(pipe_fds[0]);
        if (dup(pipe_fds[1], 1) < 0) {
             printf("sh: dup stdout to pipe failed in cmd_subst child\n");
             exit(1);
        }
        close(pipe_fds[1]);
        char temp_cmd_buffer_for_argv[MAX_INPUT_BUF];
        mystrcpy(temp_cmd_buffer_for_argv, command_to_run);
        char *sh_argv[] = {"sh.b", "-c", temp_cmd_buffer_for_argv, NULL};
        spawn("/sh.b", sh_argv);
        exit(1);
    } else {
        close(pipe_fds[1]);
        while ((r = read(pipe_fds[0], &read_char, 1)) == 1) {
            if (output_len < MAX_CMD_SUBST_OUTPUT_LEN - 1) {
                output_buffer[output_len++] = read_char;
            } else {
                debugf("sh: command substitution output too long, truncated.\n");
                while(read(pipe_fds[0], &read_char, 1) == 1);
                break;
            }
        }
        if (r < 0) {
            printf("sh: error reading from pipe in command substitution\n");
        }
        output_buffer[output_len] = '\0';

        close(pipe_fds[0]);
        wait(child_pid_for_sh_c, NULL); // Modified to match new wait signature if necessary

        while (output_len > 0 &&
               (output_buffer[output_len - 1] == '\n' || output_buffer[output_len - 1] == '\r')) {
            output_buffer[--output_len] = '\0';
        }

        for (u_int i = 0; i < output_len; ++i) {
            if (output_buffer[i] == '\n' || output_buffer[i] == '\r') {
                output_buffer[i] = ' '; // Changed from '\0' to ' '
            }
        }
        return output_buffer;
    }
    return get_subst_output_buffer();
}

void reset_allocators() {
    strdup_pool_index = 0;
    astnode_pool_index = 0;
    redirnode_pool_index = 0;
    expansion_buffer_pool_index = 0;
    cmd_subst_output_pool_idx = 0;
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

static const char *current_pos;
static Token current_token;
static Token peeked_token;
static int has_peeked_token;

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
        mystrncpy(token.value, "&&", 2);
        token.value[2] = '\0';
        current_pos += 2;
    } else if (mystrncmp(current_pos, "||", 2) == 0) {
        token.type = TOKEN_OR;
        mystrncpy(token.value, "||", 2);
        token.value[2] = '\0';
        current_pos += 2;
    } else if (mystrncmp(current_pos, ">>", 2) == 0) {
        token.type = TOKEN_REDIR_APP;
        mystrncpy(token.value, ">>", 2);
        token.value[2] = '\0';
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
    else if (*current_pos == '`') {
        token.type = TOKEN_WORD;
        int i = 0;
        token.value[i++] = *current_pos++;
        while (*current_pos && i < MAX_TOKEN_LEN - 1) {
            if (*current_pos == '`') {
                token.value[i++] = *current_pos++;
                break;
            }
            token.value[i++] = *current_pos++;
        }
        token.value[i] = '\0';
        if (i > 1 && token.value[i-1] != '`') {
            printf("sh: unclosed backtick\n");
            token.type = TOKEN_ERROR;
        } else if (i <= 1) {
             if (i==1 && token.value[0] == '`' && *current_pos == '\0') {
                token.type = TOKEN_ERROR;
             }
        }
    }
    else {
        token.type = TOKEN_WORD;
        int i = 0;
        while (*current_pos &&
               !strchr(" \t\r\n", *current_pos) &&
               !strchr("|;&<>`#", *current_pos) &&
               i < MAX_TOKEN_LEN - 1) {
             if (mystrncmp(current_pos, "&&", 2) == 0 ||
                mystrncmp(current_pos, "||", 2) == 0 ||
                mystrncmp(current_pos, ">>", 2) == 0) {
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
        peeked_token = get_next_raw_token();
        has_peeked_token = 1;
    }
    return peeked_token;
}

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
        if (!right_node && (op_type == TOKEN_SEMI || (op_type == TOKEN_AMP && current_token.type != TOKEN_EOF && current_token.type != TOKEN_EOL ) ) ) {
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

    int parent_shell_is_interactive = iscons(0);

    while (1) {
        if (current_token.type == TOKEN_WORD) {
            if (cmd_data->argc < MAX_CMD_ARGS - 1) {
                char *arg_after_var_expansion = expand_string_variables(current_token.value);
                char *final_arg_for_argv = arg_after_var_expansion;

                char rebuilt_arg_buffer[MAX_EXPANDED_STR_LEN * 2];
                rebuilt_arg_buffer[0] = '\0';
                char *current_rebuilt_ptr = rebuilt_arg_buffer;
                const char *scan_ptr = arg_after_var_expansion;

                while (*scan_ptr) {
                    char *backtick_start = strchr(scan_ptr, '`');
                    if (backtick_start) {
                        char *backtick_end = strchr(backtick_start + 1, '`');
                        if (backtick_end) {
                            if (backtick_start > scan_ptr) {
                                mystrncpy(current_rebuilt_ptr, scan_ptr, backtick_start - scan_ptr);
                                current_rebuilt_ptr += (backtick_start - scan_ptr);
                            }
                            char cmd_to_subst[MAX_INPUT_BUF];
                            int cmd_len = backtick_end - (backtick_start + 1);
                            if (cmd_len >= MAX_INPUT_BUF) cmd_len = MAX_INPUT_BUF -1;
                            mystrncpy(cmd_to_subst, backtick_start + 1, cmd_len);
                            cmd_to_subst[cmd_len] = '\0';
                            char *subst_output = execute_command_substitution(cmd_to_subst, parent_shell_is_interactive);
                            if (subst_output) {
                                mystrcat(current_rebuilt_ptr, subst_output);
                                current_rebuilt_ptr += mystrlen(subst_output);
                            }
                            scan_ptr = backtick_end + 1;
                        } else {
                            mystrcat(current_rebuilt_ptr, scan_ptr);
                            current_rebuilt_ptr += mystrlen(scan_ptr);
                            scan_ptr += mystrlen(scan_ptr);
                        }
                    } else {
                        mystrcat(current_rebuilt_ptr, scan_ptr);
                        current_rebuilt_ptr += mystrlen(scan_ptr);
                        break;
                    }
                }
                *current_rebuilt_ptr = '\0';

                if (rebuilt_arg_buffer[0] != '\0' || arg_after_var_expansion[0] == '\0') {
                    final_arg_for_argv = user_strdup(rebuilt_arg_buffer);
                } else {
                    final_arg_for_argv = user_strdup(arg_after_var_expansion);
                }
                cmd_data->argv[cmd_data->argc++] = final_arg_for_argv;
            } else { return NULL; }
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

            char *filename_after_vars = expand_string_variables(current_token.value);
            char *final_filename = filename_after_vars;
            // Apply command substitution to filenames as well
            char rebuilt_fname_buffer[MAX_EXPANDED_STR_LEN * 2];
            rebuilt_fname_buffer[0] = '\0';
            char *current_rebuilt_fname_ptr = rebuilt_fname_buffer;
            const char *scan_fname_ptr = filename_after_vars;
            while(*scan_fname_ptr){
                char *bt_start = strchr(scan_fname_ptr, '`');
                if(bt_start){
                    char *bt_end = strchr(bt_start + 1, '`');
                    if(bt_end){
                        if(bt_start > scan_fname_ptr){
                            mystrncpy(current_rebuilt_fname_ptr, scan_fname_ptr, bt_start - scan_fname_ptr);
                            current_rebuilt_fname_ptr += (bt_start - scan_fname_ptr);
                        }
                        char cmd_to_subst_fname[MAX_INPUT_BUF];
                        int cmd_len_fname = bt_end - (bt_start + 1);
                        if(cmd_len_fname >= MAX_INPUT_BUF) cmd_len_fname = MAX_INPUT_BUF -1;
                        mystrncpy(cmd_to_subst_fname, bt_start + 1, cmd_len_fname);
                        cmd_to_subst_fname[cmd_len_fname] = '\0';
                        char *subst_out_fname = execute_command_substitution(cmd_to_subst_fname, parent_shell_is_interactive);
                        if(subst_out_fname){
                            mystrcat(current_rebuilt_fname_ptr, subst_out_fname);
                            current_rebuilt_fname_ptr += mystrlen(subst_out_fname);
                        }
                        scan_fname_ptr = bt_end + 1;
                    } else {
                        mystrcat(current_rebuilt_fname_ptr, scan_fname_ptr);
                        current_rebuilt_fname_ptr += mystrlen(scan_fname_ptr);
                        break;
                    }
                } else {
                    mystrcat(current_rebuilt_fname_ptr, scan_fname_ptr);
                    current_rebuilt_fname_ptr += mystrlen(scan_fname_ptr);
                    break;
                }
            }
            *current_rebuilt_fname_ptr = '\0';
            if(rebuilt_fname_buffer[0] != '\0' || filename_after_vars[0] == '\0'){
                final_filename = user_strdup(rebuilt_fname_buffer);
            } else {
                final_filename = user_strdup(filename_after_vars);
            }
            redir_node->filename = final_filename;
            consume_token();
            *next_redir_ptr = redir_node;
            next_redir_ptr = &redir_node->next;
        } else {
            break;
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
    memset(expansion_buffer_pool[expansion_buffer_pool_index], 0, MAX_EXPANDED_STR_LEN);
    return expansion_buffer_pool[expansion_buffer_pool_index++];
}

char * expand_string_variables( char *input_str) {
    if (!input_str || !strchr(input_str, '$')) {
        return user_strdup(input_str);
    }
    char *output_buf = get_expansion_buffer();
    output_buf[0] = '\0';
    char *out_ptr = output_buf;
    const char *in_ptr = input_str;

    while (*in_ptr) {
        if (*in_ptr == '$') {
            in_ptr++;
            char var_name[MAX_VAR_NAME_LEN + 1];
            int i = 0;
            while (*in_ptr &&
                   i < MAX_VAR_NAME_LEN &&
                   !strchr(" \t\r\n$|;&<>/`", *in_ptr) // Added ` to terminators
                   ) {
                var_name[i++] = *in_ptr++;
            }
            var_name[i] = '\0';
            if (i > 0) {
                const char *var_value = get_variable_value(var_name);
                if (var_value) {
                    size_t val_len = mystrlen(var_value);
                    if ((out_ptr - output_buf) + val_len < MAX_EXPANDED_STR_LEN) {
                        mystrcpy(out_ptr, var_value);
                        out_ptr += val_len;
                    } else { /* Buffer overflow */ }
                }
            } else {
                if ((out_ptr - output_buf) < MAX_EXPANDED_STR_LEN -1) {
                    *out_ptr++ = '$';
                }
            }
        } else {
            if ((out_ptr - output_buf) < MAX_EXPANDED_STR_LEN - 1) {
                *out_ptr++ = *in_ptr++;
            } else {
                in_ptr++;
            }
        }
    }
    *out_ptr = '\0';
    return output_buf; // Returns from expansion_buffer_pool
}

int is_inner_cmd(CMDNodeData *cmd) {
	if (mystrcmp(cmd->argv[0], "cd") == 0 ||
	    mystrcmp(cmd->argv[0], "pwd") == 0 ||
	    mystrcmp(cmd->argv[0], "exit") == 0 ||
	    mystrcmp(cmd->argv[0], "declare") == 0 ||
	    mystrcmp(cmd->argv[0], "unset") == 0 ||
	    mystrcmp(cmd->argv[0], "history") == 0) {
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
            syscall_set_cwd(finalpath); // cd to root if no argument
		} else if (cmd->argc == 2) {
			char cwd[1024] = {0};
			syscall_get_cwd(cwd);
			int r;
			if ((r = get_final_path(cwd, cmd->argv[1], finalpath)) == 0) {
				syscall_set_cwd(finalpath);
			} else {
				if (r == 1) {
					printf("cd: The directory '%s' does not exist\n", cmd->argv[1]);
				} else if (r == 2) {
					printf("cd: '%s' is not a directory\n", cmd->argv[1]);
				} else if (r == -1) {
					printf("cd: error processing path (null args)\n");
				} else if (r == -2) {
					printf("cd: path too long\n");
				} else if (r == -3) {
					printf("cd: failed to normalize path\n");
				}
			}
		} else if (cmd->argc > 2) {
			printf("cd: too many arguments\n");
		}
	} else if (mystrcmp(cmd->argv[0], "exit") == 0) {
		exit(0); // Default exit with 0
	} else if (mystrcmp(cmd->argv[0], "declare") == 0) {
		int export_f = 0;
       		int readonly_f = 0;
        	int arg_idx = 1;
        	char *name_val_pair = NULL;
        	while (cmd->argv[arg_idx] && cmd->argv[arg_idx][0] == '-') {
            		if (mystrcmp(cmd->argv[arg_idx], "-x") == 0) export_f = 1;
            		else if (mystrcmp(cmd->argv[arg_idx], "-r") == 0) readonly_f = 1;
			else if (mystrcmp(cmd->argv[arg_idx], "-xr") == 0 ||
				 mystrcmp(cmd->argv[arg_idx], "-rx") == 0) {
				export_f = 1; readonly_f = 1;
			} else {
                		printf("declare: invalid option %s\n", cmd->argv[arg_idx]);
                		return;
            		}
            		arg_idx++;
        	}
        	if (cmd->argv[arg_idx]) {
            		name_val_pair = cmd->argv[arg_idx];
        	}
        	if (!name_val_pair) {
            		print_all_variables();
        	} else {
            		char name[MAX_VAR_NAME_LEN + 1];
            		char value_buf[MAX_VAR_VALUE_LEN + 1];
            		char *value_ptr = "";
            		char *eq_ptr = strchr(name_val_pair, '=');
            		if (eq_ptr) {
                		int name_len = eq_ptr - name_val_pair;
                		if (name_len > MAX_VAR_NAME_LEN) {printf("sh: var name too long\n"); return; }
                		mystrncpy(name, name_val_pair, name_len);
                		name[name_len] = '\0';
                		value_ptr = eq_ptr + 1;
                		if (mystrlen(value_ptr) > MAX_VAR_VALUE_LEN) { printf("sh: var value too long\n"); return; }
                		mystrcpy(value_buf, value_ptr);
                		value_ptr = value_buf;
            		} else {
                		if (mystrlen(name_val_pair) > MAX_VAR_NAME_LEN) { printf("sh: var name too long\n"); return; }
                		mystrcpy(name, name_val_pair);
            		}
            		set_variable(name, value_ptr, export_f, readonly_f, 1);
        	}
	} else if (mystrcmp(cmd->argv[0], "unset") == 0) {
        	if (cmd->argc != 2) {
            		printf("unset: usage: unset NAME\n");
            		return;
        	}
        	unset_variable(cmd->argv[1]);
    	} else if (mystrcmp(cmd->argv[0], "history") == 0) {
 		if (cmd->argc > 1) {
        		printf("history: too many arguments\n");
        		return;
    		}
    		int start_idx;
    		if (history_count == 0) return;
    		if (history_count < HISTFILESIZE) start_idx = 0;
    		else start_idx = history_add_idx;
    		for (int i = 0; i < history_count; ++i) {
        		int current_entry_idx = (start_idx + i) % HISTFILESIZE;
        		printf("%s\n", history_lines[current_entry_idx]);
    		}
	}
}

int get_final_path(const char *cwd, const char *path, char *finalpath) {
    if (!cwd || !path || !finalpath) return -1;
    char constructed_path[MAXPATHLEN * 2];
    if (path[0] == '/') {
        if (mystrlen(path) >= MAXPATHLEN) return -2;
        mystrcpy(constructed_path, path);
    } else {
        if (mystrlen(cwd) + 1 + mystrlen(path) + 1 > sizeof(constructed_path)) return -2;
        mystrcpy(constructed_path, cwd);
        if (mystrcmp(cwd, "/") != 0 && constructed_path[mystrlen(constructed_path) - 1] != '/') {
            mystrcat(constructed_path, "/");
        }
        mystrcat(constructed_path, path);
    }
    if (normalize_path(constructed_path) < 0) return -3;
    if (path[0] != '/') { // Only stat if original path was relative for cd behavior
        struct Stat st;
        int r_stat = stat(constructed_path, &st);
        if (r_stat < 0) return 1;
        if (st.st_isdir == 0) return 2;
    }
    mystrcpy(finalpath, constructed_path);
    return 0;
}

int normalize_path(char *path_buf) {
    if (path_buf == NULL) return -1;
    char components[MAX_CMD_ARGS][MAXNAMELEN];
    int comp_idx = 0;
    const char *p = path_buf;
    int is_absolute = (*p == '/');

    if (is_absolute) {
        p++; while (*p == '/') p++;
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
            if (comp_idx > 0 && mystrcmp(components[comp_idx - 1], "..") != 0) comp_idx--;
            else if (!is_absolute) {
                if (comp_idx < MAX_CMD_ARGS) mystrncpy(components[comp_idx++], "..", MAXNAMELEN-1);
                else return -E_BAD_PATH;
            }
        } else if (mystrcmp(current_comp_val, ".") != 0 && current_comp_val[0] != '\0') {
            if (comp_idx < MAX_CMD_ARGS) mystrncpy(components[comp_idx++], current_comp_val, MAXNAMELEN-1);
            else return -E_BAD_PATH;
        }
        while (*p == '/') p++;
    }
    char *write_ptr = path_buf;
    if (is_absolute) *write_ptr++ = '/';
    for (int i = 0; i < comp_idx; i++) {
        if (i > 0 || (is_absolute && comp_idx > 0 && i==0 && write_ptr > path_buf && *(write_ptr-1) != '/')) { // ensure slash for non-first components or if root isn't only thing
             if(write_ptr == path_buf && is_absolute && *path_buf == '/'){/* no extra slash if only / */}
             else if (write_ptr > path_buf && *(write_ptr-1) != '/') {
                if (write_ptr - path_buf >= MAXPATHLEN -1) return -E_BAD_PATH;
                *write_ptr++ = '/';
             } else if (write_ptr == path_buf && !is_absolute && i > 0) { // relative path, non-first component
                if (write_ptr - path_buf >= MAXPATHLEN -1) return -E_BAD_PATH;
                 *write_ptr++ = '/';
             }
        }
        int len = mystrlen(components[i]);
        if ((write_ptr - path_buf) + len >= MAXPATHLEN) return -E_BAD_PATH;
        memcpy(write_ptr, components[i], len);
        write_ptr += len;
    }
    *write_ptr = '\0';
    if (path_buf[0] == '\0') {
        if (is_absolute) mystrcpy(path_buf, "/");
        else mystrcpy(path_buf, ".");
    } else if (is_absolute && write_ptr == path_buf + 1 && path_buf[0] == '/' && comp_idx == 0) {
        // Path was like "//" or "/./" or "/foo/..", normalized to just "/"
        // Ensure it's exactly "/" and not "/\0" if write_ptr is path_buf+1
    } else if (is_absolute && path_buf[0] == '/' && path_buf[1] == '/' && path_buf[2] == '\0'){ // Fix "///" to "/"
	path_buf[1] = '\0';
    }


    return 0;
}

void execute_ast(ASTNode *node) {
    if (!node) {
        return;
    }
    int child_pid;
    int pipe_fds[2];

    switch (node->type) {
        case NODE_COMMAND: {
            CMDNodeData *cmd = &node->data.command;
            if (cmd->argc == 0 && cmd->redirects == NULL) return;
            if (cmd->argc == 0 && cmd->redirects != NULL) {
                 // Handle redirection-only command if necessary, or error
                 // For now, if no command, but redirects, it's tricky.
                 // Bash creates files but doesn't run anything. Let's assume error for simplicity.
                 debugf("sh: missing command for redirection\n");
                 return;
            }
	    if (is_inner_cmd(cmd)) {
	    	execute_inner_cmd(cmd);
		break;
	    }
            child_pid = fork();
            if (child_pid < 0) user_panic("execute_ast: fork failed");

            if (child_pid == 0) {
                RedirNode *redir = cmd->redirects;
                while (redir) {
                    int open_flags = 0;
                    int target_fd_std = -1;
                    if (redir->type == REDIR_TYPE_IN) { open_flags = O_RDONLY; target_fd_std = 0; }
                    else if (redir->type == REDIR_TYPE_OUT) { open_flags = O_WRONLY | O_CREAT | O_TRUNC; target_fd_std = 1; }
                    else if (redir->type == REDIR_TYPE_APP) { open_flags = O_WRONLY | O_CREAT | O_APPEND; target_fd_std = 1; }
                    int opened_fd = open(redir->filename, open_flags);
                    if (opened_fd < 0) { printf("sh: cannot open %s\n", redir->filename); exit(1); }
                    dup(opened_fd, target_fd_std);
                    close(opened_fd);
                    redir = redir->next;
                }
		int spawn_ret;
		char *spawn_argv[MAX_CMD_ARGS + MAX_SHELL_VARS + 1];
		int spawn_argc = 0;
		if (mystrcmp(cmd->argv[0], "sh.b") == 0 || mystrcmp(cmd->argv[0], "sh") == 0 ||
		    mystrcmp(cmd->argv[0], "/sh.b") == 0 || mystrcmp(cmd->argv[0], "/sh") == 0) {
            for (int i = 0; i < cmd->argc; ++i) spawn_argv[spawn_argc++] = cmd->argv[i];
            char env_str_pool[MAX_SHELL_VARS][MAX_VAR_NAME_LEN + MAX_VAR_VALUE_LEN + 3]; // +2 for =,\0, +1 for readonly flag
            int env_str_idx = 0;
            for (int i = 0; i < MAX_SHELL_VARS; ++i) {
                if (shell_vars[i].is_set && shell_vars[i].is_exported) {
                    if (spawn_argc < (MAX_CMD_ARGS + MAX_SHELL_VARS) && env_str_idx < MAX_SHELL_VARS) {
                        char *current_env_str = env_str_pool[env_str_idx++];
                        current_env_str[0] = shell_vars[i].is_readonly ? '1' : '0'; // Prepend readonly flag
                        current_env_str[1] = '\0'; // Null terminate after flag
                        mystrcat(current_env_str, shell_vars[i].name);
                        mystrcat(current_env_str, "=");
                        mystrcat(current_env_str, shell_vars[i].value);
                        spawn_argv[spawn_argc++] = current_env_str;
                    } else break;
                }
            }
            spawn_argv[spawn_argc] = NULL;
			spawn_ret = spawn(cmd->argv[0], spawn_argv);
		} else {
               		spawn_ret = spawn(cmd->argv[0], (char **)cmd->argv);
		}
                if (spawn_ret < 0) {
                    printf("sh: failed to spawn '%s' (err %d)\n", cmd->argv[0], spawn_ret);
                    exit(127); // Standard for command not found
                }
                exit(0); // Default success if spawn *somehow* returns but didn't error.
            } else {
                wait(child_pid, NULL); // Parent waits, ignore status for now
            }
            break;
        }
        case NODE_PIPELINE: {
            if (pipe(pipe_fds) < 0) user_panic("pipe creation failed");
            int pid1 = fork();
            if (pid1 < 0) user_panic("fork for pipe left failed");
            if (pid1 == 0) {
                close(pipe_fds[0]); dup(pipe_fds[1], 1); close(pipe_fds[1]);
                execute_ast(node->data.binary_op.left); exit(0);
            }
            int pid2 = fork();
            if (pid2 < 0) user_panic("fork for pipe right failed");
            if (pid2 == 0) {
                close(pipe_fds[1]); dup(pipe_fds[0], 0); close(pipe_fds[0]);
                execute_ast(node->data.binary_op.right); exit(0);
            }
            close(pipe_fds[0]); close(pipe_fds[1]);
            wait(pid1, NULL); wait(pid2, NULL);
            break;
        }
        case NODE_LIST_SEMI:
            execute_ast(node->data.binary_op.left);
            if (node->data.binary_op.right) execute_ast(node->data.binary_op.right);
            break;
        case NODE_LIST_AMP:
            child_pid = fork();
            if (child_pid < 0) user_panic("fork for & failed");
            if (child_pid == 0) { execute_ast(node->data.binary_op.left); exit(0); }
            if (node->data.binary_op.right) execute_ast(node->data.binary_op.right);
            break;
        case NODE_AND:
            execute_ast(node->data.binary_op.left); // Needs status
            if (node->data.binary_op.right) execute_ast(node->data.binary_op.right); // Temp
            break;
        case NODE_OR:
            execute_ast(node->data.binary_op.left); // Needs status
            if (node->data.binary_op.right) execute_ast(node->data.binary_op.right); // Temp
            break;
        default:
            user_panic("Unknown AST node type: %d", node->type);
    }
}

char outbuf[20000];
char now_cmd_buf[1025];

int all_line_count;
int now_line_index;
char all_lines[25][1025];
char copy_buf[1024];

void readline(char *buf, u_int n, int interactive) {
    int r;
    u_int current_len; 
    u_int cursor_pos;  
    char c;
    u_int onscreen_cmd_len = 0; 

    if (n == 0) return;

    if (history_current_nav_offset == 0) { 
        mystrcpy(buf, current_typed_line); 
    } else {
        int nav_idx_in_hist_array = (history_latest_idx - (history_current_nav_offset - 1) + HISTFILESIZE) % HISTFILESIZE;
        if (history_count > 0 && history_current_nav_offset <= history_count) { 
             mystrcpy(buf, history_lines[nav_idx_in_hist_array]);
        } else { 
            buf[0] = '\0';
        }
    }
    current_len = mystrlen(buf);
    cursor_pos = current_len; 

    if (interactive && current_len > 0) {
        printf("\r$ "); 
        for (u_int i = 0; i < current_len; ++i) printf("%c", buf[i]);
        onscreen_cmd_len = current_len;
    }


    for (;;) {
        if ((r = read(0, &c, 1)) != 1) {
            if (r <= 0) { 
                if (interactive && current_len == 0 && r == 0) printf("exit\n");
                exit(0);
            }
            buf[current_len] = 0; return; 
        }

        int requires_full_reprint = 0;

        if (c != 0x1b) { 
            if (history_current_nav_offset != 0) {
                mystrcpy(current_typed_line, buf); 
                history_current_nav_offset = 0;    
            }
        }


        if (c == 0x1b) { 
            char seq[2];
            if (read(0, &seq[0], 1) != 1) continue;
            if (seq[0] == '[') {
                if (read(0, &seq[1], 1) != 1) continue;

                if (seq[1] == 'A') { 
                    if (history_count > 0) {
                        if (history_current_nav_offset == 0) { 
                            mystrcpy(current_typed_line, buf); 
                        }
                        if (history_current_nav_offset < history_count) {
                            history_current_nav_offset++;
                            int nav_idx_in_hist_array = (history_latest_idx - (history_current_nav_offset - 1) + HISTFILESIZE) % HISTFILESIZE;
                            mystrcpy(buf, history_lines[nav_idx_in_hist_array]);
                            current_len = mystrlen(buf);
                            cursor_pos = current_len;
                            requires_full_reprint = 1;
                        }
                    }
                } else if (seq[1] == 'B') { 
                    if (history_current_nav_offset > 0) {
                        history_current_nav_offset--;
                        if (history_current_nav_offset == 0) { 
                            mystrcpy(buf, current_typed_line);
                        } else {
                            int nav_idx_in_hist_array = (history_latest_idx - (history_current_nav_offset - 1) + HISTFILESIZE) % HISTFILESIZE;
                            mystrcpy(buf, history_lines[nav_idx_in_hist_array]);
                        }
                        current_len = mystrlen(buf);
                        cursor_pos = current_len;
                        requires_full_reprint = 1;
                    }
                } else if (seq[1] == 'D') { 
                    if (cursor_pos > 0) {
                        cursor_pos--;
                        requires_full_reprint = 1;
                    }
                } else if (seq[1] == 'C') { 
                    if (cursor_pos < current_len) {
                        cursor_pos++;
                        requires_full_reprint = 1;
                    }
                }
            }
        } else if (c == '\b' || c == 0x7f) { 
             if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf); 
                history_current_nav_offset = 0;
            }
            if (cursor_pos > 0) {
                mymemmove(&buf[cursor_pos - 1], &buf[cursor_pos], current_len - cursor_pos + 1);
                cursor_pos--;
                current_len--;
                requires_full_reprint = 1;
            }
        } else if (c == 0x01) { 
            if (cursor_pos != 0) { cursor_pos = 0; requires_full_reprint = 1;}
        } else if (c == 0x05) { 
            if (cursor_pos != current_len) { cursor_pos = current_len; requires_full_reprint = 1;}
        } else if (c == 0x0B) { 
             if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf);
                history_current_nav_offset = 0;
            }
            if (cursor_pos < current_len) {
                buf[cursor_pos] = '\0'; current_len = cursor_pos; requires_full_reprint = 1;
            }
        } else if (c == 0x15) { 
            if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf);
                history_current_nav_offset = 0;
            }
            if (cursor_pos > 0) {
                mymemmove(&buf[0], &buf[cursor_pos], current_len - cursor_pos + 1);
                current_len -= cursor_pos; cursor_pos = 0; requires_full_reprint = 1;
            }
        } else if (c == 0x17) { 
            if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf);
                history_current_nav_offset = 0;
            }
            if (cursor_pos > 0) {
                u_int original_cursor_pos = cursor_pos;
                u_int end_of_deletion_span = cursor_pos;
                while (cursor_pos > 0 && strchr(" \t", buf[cursor_pos - 1])) cursor_pos--;
                u_int start_of_word_to_delete = cursor_pos;
                while (start_of_word_to_delete > 0 && !strchr(" \t", buf[start_of_word_to_delete - 1])) {
                    start_of_word_to_delete--;
                }
                if (start_of_word_to_delete < end_of_deletion_span) {
                    mymemmove(&buf[start_of_word_to_delete], &buf[end_of_deletion_span], current_len - end_of_deletion_span + 1);
                    current_len -= (end_of_deletion_span - start_of_word_to_delete);
                    cursor_pos = start_of_word_to_delete;
                    requires_full_reprint = 1;
                } else {
                    cursor_pos = original_cursor_pos;
                }
            }
        } else if (c == '\r' || c == '\n') { 
            buf[current_len] = 0;
            if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf); 
            } else { 
                mystrcpy(current_typed_line, buf); 
            }
            if (interactive) printf("\n");
            return;
        } else if (c >= 0x20 && c < 0x7f) { 
            if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf);
                history_current_nav_offset = 0; 
            }
            if (current_len < n - 1) {
                if (cursor_pos < current_len) {
                    mymemmove(&buf[cursor_pos + 1], &buf[cursor_pos], current_len - cursor_pos + 1);
                }
                buf[cursor_pos] = c;
                current_len++;
                cursor_pos++;
                requires_full_reprint = 1;
            }
        }

        if (requires_full_reprint && interactive) {
            printf("\r");
            printf("$ ");

            for (u_int i = 0; i < current_len; ++i) {
                printf("%c", buf[i]);
            }

            if (current_len < onscreen_cmd_len) {
                for (u_int i = 0; i < (onscreen_cmd_len - current_len); ++i) {
                    printf(" ");
                }
            }

            u_int effective_displayed_cmd_len = (current_len > onscreen_cmd_len) ? current_len : onscreen_cmd_len;
            for (u_int i = 0; i < (effective_displayed_cmd_len - cursor_pos); ++i) {
                printf("\b");
            }
            onscreen_cmd_len = current_len;
        }
    }
}

char input_buf[MAX_INPUT_BUF];

void usage(void) {
    printf("usage: sh [-ix] [script-file]\n");
    exit(0);
}

void load_history() {
    int fd, r, i;
    char line_buf[MAX_INPUT_BUF];
    int line_len = 0;
    char c;

    history_count = 0;
    history_add_idx = 0;
    history_latest_idx = -1;

    fd = open(HISTORY_FILE, O_RDONLY);
    if (fd < 0) {
        return;
    }

    char temp_history_load[HISTFILESIZE][MAX_INPUT_BUF];
    int temp_count = 0;

    while ((r = read(fd, &c, 1)) == 1) {
        if (c == '\n') {
            if (line_len > 0) {
                line_buf[line_len] = '\0';
                if (temp_count < HISTFILESIZE) {
                    mystrcpy(temp_history_load[temp_count++], line_buf);
                } else {
                    for(i = 0; i < HISTFILESIZE - 1; ++i) {
                        mystrcpy(temp_history_load[i], temp_history_load[i+1]);
                    }
                    mystrcpy(temp_history_load[HISTFILESIZE-1], line_buf);
                }
                line_len = 0;
            }
        } else if (line_len < MAX_INPUT_BUF - 1) {
            line_buf[line_len++] = c;
        }
    }
    if (line_len > 0) {
        line_buf[line_len] = '\0';
        if (temp_count < HISTFILESIZE) {
            mystrcpy(temp_history_load[temp_count++], line_buf);
        } else {
             for(i = 0; i < HISTFILESIZE - 1; ++i) {
                mystrcpy(temp_history_load[i], temp_history_load[i+1]);
            }
            mystrcpy(temp_history_load[HISTFILESIZE-1], line_buf);
        }
    }

    for (i = 0; i < temp_count; ++i) {
        mystrcpy(history_lines[history_add_idx], temp_history_load[i]);
        history_latest_idx = history_add_idx;
        history_add_idx = (history_add_idx + 1) % HISTFILESIZE;
        if (history_count < HISTFILESIZE) {
            history_count++;
        }
    }
    close(fd);
    history_current_nav_offset = 0;
}

void save_history() {
    int fd, i, r;
    int start_idx;

    fd = open(HISTORY_FILE, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        printf("sh: error saving history to %s\n", HISTORY_FILE);
        return;
    }

    if (history_count == 0) {
        close(fd);
        return;
    }

    if (history_count < HISTFILESIZE) {
        start_idx = 0;
    } else {
        start_idx = history_add_idx;
    }

    for (i = 0; i < history_count; ++i) {
        int current_entry_idx = (start_idx + i) % HISTFILESIZE;
        r = write(fd, history_lines[current_entry_idx], mystrlen(history_lines[current_entry_idx]));
        if (r < 0) break;
        r = write(fd, "\n", 1);
        if (r < 0) break;
    }
    close(fd);
}

void add_to_history(const char *cmd_line) {
    if ( cmd_line[0] == '\0') return;

    if (history_count > 0 && mystrcmp(history_lines[history_latest_idx], cmd_line) == 0) {
        history_current_nav_offset = 0; // Still reset nav offset
        return;
    }

    mystrcpy(history_lines[history_add_idx], cmd_line);
    history_latest_idx = history_add_idx;
    history_add_idx = (history_add_idx + 1) % HISTFILESIZE;
    if (history_count < HISTFILESIZE) {
        history_count++;
    }
    history_current_nav_offset = 0;
}

int main(int argc, char **argv) {
    init_shell_vars();
    int interactive = iscons(0);
    int echocmds = 0;
    char *command_string_from_arg = NULL;
    int arg_idx_after_opts = 1;

    if (argc > 1 && mystrcmp(argv[1], "-c") == 0) {
        if (argc > 2) {
            command_string_from_arg = argv[2];
            interactive = 0;
            // Process other options if any for sh -c ... sh_options ... "cmd" arg1 arg2
            // For now, assume argv[0]=sh, argv[1]=-c, argv[2]=cmd_string
        } else {
            printf("sh: -c option requires an argument\n");
            exit(1);
        }
    } else if (argc > 1 && argv[1][0] != '-') { // Potential script file if not an option
         // This logic needs to be integrated with ARGBEGIN or done before.
         // Simplified: If first arg after "sh" is not an option, assume it's a script file.
    }


    if (command_string_from_arg) {
        reset_allocators();
        mystrcpy(input_buf, command_string_from_arg);
        if (echocmds) printf("+ %s\n", input_buf);
        const char* temp_scan = input_buf;
        while (*temp_scan && strchr(WHITESPACE, *temp_scan)) temp_scan++;
        if (*temp_scan != '#' && *temp_scan != '\0') {
            tokenizer_init(input_buf);
            ASTNode *ast = parse_line();
            if (ast) execute_ast(ast);
            else if (input_buf[0] != '\0') printf("sh: syntax error in command string\n");
        }
        exit(0); // Shell exits after -c
    }
    if (!command_string_from_arg) { // only parse options if not already in -c mode
        ARGBEGIN {
        case 'i': interactive = 1; break;
        case 'x': echocmds = 1; break;
        default: usage();
        } ARGEND
        arg_idx_after_opts = ARGC();
    }
    for (int i = arg_idx_after_opts; i < argc; ++i) {
        char *arg = argv[i];
        if (arg[0] == '-' && (arg[1] == 'c' || arg[1] == 'i' || arg[1] == 'x')) {
             if (arg[1] == 'c' && i + 1 < argc) i++; // skip command string for -c
             continue;
        }

        char *eq_ptr = strchr(arg, '=');
        if (eq_ptr && (eq_ptr != arg) && strchr(arg, '/') == NULL && strlen(arg) > 2) { // Heuristic for env var
            char name[MAX_VAR_NAME_LEN + 1];
            char value_buf[MAX_VAR_VALUE_LEN + 1];
            int is_ro_flag = arg[0] - '0'; // First char is '0' or '1' for readonly
            const char *name_start = arg + 1; // Name starts after the flag

            int name_len = eq_ptr - name_start;
            if (name_len > 0 && name_len <= MAX_VAR_NAME_LEN) {
                mystrncpy(name, name_start, name_len);
                name[name_len] = '\0';
                if (mystrlen(eq_ptr + 1) <= MAX_VAR_VALUE_LEN) {
                    mystrcpy(value_buf, eq_ptr + 1);
                    set_variable(name, value_buf, 1, is_ro_flag, 0);
                } else { /* value too long, skip */ }
            } else { /* name too long or empty, skip */ }
            arg_idx_after_opts = i + 1; // Update index of potential script file
        } else {
            // This is now considered the script file if present
            break;
        }
    }


    if (argc > arg_idx_after_opts && !command_string_from_arg) { // Script file if not -c mode
        close(0);
        int r_open = open(argv[arg_idx_after_opts], O_RDONLY);
        if (r_open < 0) user_panic("open %s: %d", argv[arg_idx_after_opts], r_open);
        if (r_open != 0) { dup(r_open, 0); close(r_open); }
        interactive = 0;
    }

    if (interactive){
        printf("\n:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");
        printf("::                                                         ::\n");
        printf("::                 MOS Shell (Command Control)             ::\n");
        printf("::                                                         ::\n");
        printf(":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");
    }

    load_history();
    int first_prompt_cycle = 1;

    for (;;) {
        reset_allocators();
        memset(input_buf, 0, sizeof(input_buf));

        if (interactive) {
            if (first_prompt_cycle) printf("\n$ ");
            else printf("$ ");
        }

    	if (history_current_nav_offset == 0) {
            current_typed_line[0] = '\0';
        }
        readline(input_buf, sizeof input_buf, interactive);

        if (input_buf[0] == '\0') {
            if (interactive) {
                first_prompt_cycle = 0; continue;
            } else {
                 exit(0);
            }
        }
        first_prompt_cycle = 1;

        if (echocmds) {
            printf("+ %s\n", input_buf);
        }

        const char* temp_scan = input_buf;
        while (*temp_scan && strchr(WHITESPACE, *temp_scan)) temp_scan++;
        if (*temp_scan == '#' || *temp_scan == '\0') {
            first_prompt_cycle = 0; // Comment or empty line, next prompt doesn't need extra \n
            continue;
        }

	    add_to_history(input_buf);
        save_history();
        tokenizer_init(input_buf);
        ASTNode *ast = parse_line();

        if (ast) {
            execute_ast(ast);
        } else {
            if(input_buf[0] != '\0' && input_buf[0] != '#') {
                 if (current_token.type != TOKEN_EOF && current_token.type != TOKEN_EOL && current_token.type != TOKEN_ERROR && current_token.type != 0 ) {
                    printf("sh: syntax error near token '%s'\n", current_token.value);
                 } else if (current_token.type == TOKEN_ERROR && current_token.value[0] != '\0'){
                    printf("sh: tokenizer error near '%s'\n", current_token.value);
                 } else if (current_token.type != TOKEN_EOF && current_token.type != TOKEN_EOL){
                    printf("sh: syntax error\n");
                 }
            }
        }
    }
    return 0;
}

int mystrncpy(char* dest, const char* src, int count) {
	char* start = dest;
	while (count && (*dest++ = *src++)) {
		count--;
	}
	if (count) {
		while (--count) {
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
    while (*ptr != '\0') ptr++;
    while ((*ptr++ = *src++) != '\0');
    return 0;
}

int mystrcpy(char* dest, const char* src) {
    while ((*dest++ = *src++) != '\0');
    return 0;
}

int mystrlen(const char *str) {
    size_t length = 0;
    while (str[length] != '\0') length++;
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
        if (!shell_vars[i].is_set) return &shell_vars[i];
    }
    return NULL;
}

int set_variable(const char *name, const char *value, int export_flag, int readonly_flag, int update_flags_if_exists) {
    if (mystrlen(name) > MAX_VAR_NAME_LEN) return -1;
    if (value && mystrlen(value) > MAX_VAR_VALUE_LEN) return -1;

    ShellVar *var = find_variable(name);
    if (var) {
        if (var->is_readonly) return -1;
        mystrcpy(var->value, value ? value : "");
        if (update_flags_if_exists) {
            var->is_exported = export_flag;
            if (readonly_flag) var->is_readonly = 1;
        }
    } else {
        var = find_free_slot();
        if (!var) return -1;
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
    if (!var) return -1;
    if (var->is_readonly) return -1;
    var->is_set = 0;
    var->name[0] = '\0';
    num_set_vars--;
    return 0;
}

void print_all_variables() {
    for (int i = 0; i < MAX_SHELL_VARS; ++i) {
        if (shell_vars[i].is_set) {
            printf("%s%s%s=%s\n",
                   shell_vars[i].is_exported ? "" : "",
                   shell_vars[i].is_readonly ? "" : "",
                   shell_vars[i].name,
                   shell_vars[i].value);
        }
    }
}

char* get_variable_value(const char *name) {
    ShellVar *var = find_variable(name);
    if (var && var->is_set) return var->value;
    return NULL;
}

char *mystrchr(const char *str, char c) {
    while (*str) {
        if (*str == c) return (char *)str;
        str++;
    }
    if (c == '\0') return (char *)str;
    return NULL;
}

void *mymemmove(void *dest, const void *src, int n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        for (int i = 0; i < n; i++) d[i] = s[i];
    } else if (d > s) {
        for (int i = n; i > 0; i--) d[i - 1] = s[i - 1];
    }
    return dest;
}
```

整个架构流程大致可以分为：**输入读入(readline)，生成AST树(parse_line)，执行AST树(execute_ast)，执行内部指令(execute_inner_command)/外部指令(spawn)。**

首先是输入读入，调用readline函数来完成从标准输入中读入，readline函数如下（实现了快捷键）：

```C
void readline(char *buf, u_int n, int interactive) {
    int r;
    u_int current_len; 
    u_int cursor_pos;  
    char c;
    u_int onscreen_cmd_len = 0; 

    if (n == 0) return;

    if (history_current_nav_offset == 0) { 
        mystrcpy(buf, current_typed_line); 
    } else {
        int nav_idx_in_hist_array = (history_latest_idx - (history_current_nav_offset - 1) + HISTFILESIZE) % HISTFILESIZE;
        if (history_count > 0 && history_current_nav_offset <= history_count) { 
             mystrcpy(buf, history_lines[nav_idx_in_hist_array]);
        } else { 
            buf[0] = '\0';
        }
    }
    current_len = mystrlen(buf);
    cursor_pos = current_len; 

    if (interactive && current_len > 0) {
        printf("\r$ "); 
        for (u_int i = 0; i < current_len; ++i) printf("%c", buf[i]);
        onscreen_cmd_len = current_len;
    }


    for (;;) {
        if ((r = read(0, &c, 1)) != 1) {
            if (r <= 0) { 
                if (interactive && current_len == 0 && r == 0) printf("exit\n");
                exit(0);
            }
            buf[current_len] = 0; return; 
        }

        int requires_full_reprint = 0;

        if (c != 0x1b) { 
            if (history_current_nav_offset != 0) {
                mystrcpy(current_typed_line, buf); 
                history_current_nav_offset = 0;    
            }
        }


        if (c == 0x1b) { 
            char seq[2];
            if (read(0, &seq[0], 1) != 1) continue;
            if (seq[0] == '[') {
                if (read(0, &seq[1], 1) != 1) continue;

                if (seq[1] == 'A') { 
                    if (history_count > 0) {
                        if (history_current_nav_offset == 0) { 
                            mystrcpy(current_typed_line, buf); 
                        }
                        if (history_current_nav_offset < history_count) {
                            history_current_nav_offset++;
                            int nav_idx_in_hist_array = (history_latest_idx - (history_current_nav_offset - 1) + HISTFILESIZE) % HISTFILESIZE;
                            mystrcpy(buf, history_lines[nav_idx_in_hist_array]);
                            current_len = mystrlen(buf);
                            cursor_pos = current_len;
                            requires_full_reprint = 1;
                        }
                    }
                } else if (seq[1] == 'B') { 
                    if (history_current_nav_offset > 0) {
                        history_current_nav_offset--;
                        if (history_current_nav_offset == 0) { 
                            mystrcpy(buf, current_typed_line);
                        } else {
                            int nav_idx_in_hist_array = (history_latest_idx - (history_current_nav_offset - 1) + HISTFILESIZE) % HISTFILESIZE;
                            mystrcpy(buf, history_lines[nav_idx_in_hist_array]);
                        }
                        current_len = mystrlen(buf);
                        cursor_pos = current_len;
                        requires_full_reprint = 1;
                    }
                } else if (seq[1] == 'D') { 
                    if (cursor_pos > 0) {
                        cursor_pos--;
                        requires_full_reprint = 1;
                    }
                } else if (seq[1] == 'C') { 
                    if (cursor_pos < current_len) {
                        cursor_pos++;
                        requires_full_reprint = 1;
                    }
                }
            }
        } else if (c == '\b' || c == 0x7f) { 
             if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf); 
                history_current_nav_offset = 0;
            }
            if (cursor_pos > 0) {
                mymemmove(&buf[cursor_pos - 1], &buf[cursor_pos], current_len - cursor_pos + 1);
                cursor_pos--;
                current_len--;
                requires_full_reprint = 1;
            }
        } else if (c == 0x01) { 
            if (cursor_pos != 0) { cursor_pos = 0; requires_full_reprint = 1;}
        } else if (c == 0x05) { 
            if (cursor_pos != current_len) { cursor_pos = current_len; requires_full_reprint = 1;}
        } else if (c == 0x0B) { 
             if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf);
                history_current_nav_offset = 0;
            }
            if (cursor_pos < current_len) {
                buf[cursor_pos] = '\0'; current_len = cursor_pos; requires_full_reprint = 1;
            }
        } else if (c == 0x15) { 
            if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf);
                history_current_nav_offset = 0;
            }
            if (cursor_pos > 0) {
                mymemmove(&buf[0], &buf[cursor_pos], current_len - cursor_pos + 1);
                current_len -= cursor_pos; cursor_pos = 0; requires_full_reprint = 1;
            }
        } else if (c == 0x17) { 
            if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf);
                history_current_nav_offset = 0;
            }
            if (cursor_pos > 0) {
                u_int original_cursor_pos = cursor_pos;
                u_int end_of_deletion_span = cursor_pos;
                while (cursor_pos > 0 && strchr(" \t", buf[cursor_pos - 1])) cursor_pos--;
                u_int start_of_word_to_delete = cursor_pos;
                while (start_of_word_to_delete > 0 && !strchr(" \t", buf[start_of_word_to_delete - 1])) {
                    start_of_word_to_delete--;
                }
                if (start_of_word_to_delete < end_of_deletion_span) {
                    mymemmove(&buf[start_of_word_to_delete], &buf[end_of_deletion_span], current_len - end_of_deletion_span + 1);
                    current_len -= (end_of_deletion_span - start_of_word_to_delete);
                    cursor_pos = start_of_word_to_delete;
                    requires_full_reprint = 1;
                } else {
                    cursor_pos = original_cursor_pos;
                }
            }
        } else if (c == '\r' || c == '\n') { 
            buf[current_len] = 0;
            if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf); 
            } else { 
                mystrcpy(current_typed_line, buf); 
            }
            if (interactive) printf("\n");
            return;
        } else if (c >= 0x20 && c < 0x7f) { 
            if (history_current_nav_offset != 0) { 
                mystrcpy(current_typed_line, buf);
                history_current_nav_offset = 0; 
            }
            if (current_len < n - 1) {
                if (cursor_pos < current_len) {
                    mymemmove(&buf[cursor_pos + 1], &buf[cursor_pos], current_len - cursor_pos + 1);
                }
                buf[cursor_pos] = c;
                current_len++;
                cursor_pos++;
                requires_full_reprint = 1;
            }
        }

        if (requires_full_reprint && interactive) {
            printf("\r");
            printf("$ ");

            for (u_int i = 0; i < current_len; ++i) {
                printf("%c", buf[i]);
            }

            if (current_len < onscreen_cmd_len) {
                for (u_int i = 0; i < (onscreen_cmd_len - current_len); ++i) {
                    printf(" ");
                }
            }

            u_int effective_displayed_cmd_len = (current_len > onscreen_cmd_len) ? current_len : onscreen_cmd_len;
            for (u_int i = 0; i < (effective_displayed_cmd_len - cursor_pos); ++i) {
                printf("\b");
            }
            onscreen_cmd_len = current_len;
        }
    }
}
```

然后是解析输入。首先需要明确AST语法树的结构和节点内容：

整体的思路是递归下降，先定义出最小的Token单元，然后用get_new_raw_token来获取下一个Token，最后根据当前的token来构建不同的ASTNode节点。

枚举类型如下：

```C
typedef struct ASTNode ASTNode;
// --- AST Node Types Enum ---
typedef enum {
    NODE_ILLEGAL = 0,
    NODE_COMMAND,
    NODE_PIPELINE,
    NODE_LIST_SEMI,  // For ';'
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
    TOKEN_AND,         // &&
    TOKEN_OR,          // ||
    TOKEN_REDIR_IN,    // <
    TOKEN_REDIR_OUT,   // >
    TOKEN_REDIR_APP,   // >>
} TokenType;
typedef enum {
    REDIR_TYPE_IN,   // <
    REDIR_TYPE_OUT,  // >
    REDIR_TYPE_APP,  // >>
} RedirType;
```

包含了ASTNodeType，用来标记ASTNode的节点类型。TokenType，用来标记每个token的类型。

之后是ASTNode和Token结构定义。
**Token**包含一个TokenType，用来标志Token的类型，以及一个value。如果TokenType是TOKEN_WORD，那么这个字符串会被存到value中。
**ASTNode**包含一个ASTNodeType，用来标志这个ASTNode节点的类型，以及data。data分为两种，如果是command类型，则data是CMDNodeData；如果是；&& || |，那么data是BinaryOpNodeData。
**CMDNodeData**包括argv，用来涵盖一个指令的几个由空白字符分割的片段，argv[0]是指令的名字，后面是指令参数。argc是有效argv的数目，RedirNode是指令中包含的重定向指针。
**BinaryOpNodeData**类似于二叉树，由左右节点组成，类型都是ASTNode。
**RedirNode**包含重定向的类型RedirType，用来区分 < > >>，同时还有重定向操作的文件名filename，同时还有指向下一个RedirNode的指针，用来链式存储连续重定向。
代码如下：

```C
// --- Token Structure ---
typedef struct {
    TokenType type;
    char value[MAX_TOKEN_LEN]; // String value of the token
} Token;
// --- Redirection Structure ---
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
```

解析层级如下：
parse_line = parse_list
parse_list = parse_and_or ( ; parse_and_or)
parse_and_or = parse_pipeline ( &&/| | parse_pipeline)
parse_pipeline = parse_command ( | parse_command)
parse_command = command (redirect command)

具体函数实现如下：

```C
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
    
    int parent_shell_is_interactive = iscons(0);
    while (1) { // Changed to infinite loop, break out explicitly
        if (current_token.type == TOKEN_WORD) {
		if (cmd_data->argc < MAX_CMD_ARGS - 1) {
                char *arg_after_var_expansion = expand_string_variables(current_token.value);
                char *final_arg_for_argv = arg_after_var_expansion; // Start with variable-expanded arg
                char rebuilt_arg_buffer[MAX_EXPANDED_STR_LEN * 2]; // Temporary buffer for rebuilding arg
                rebuilt_arg_buffer[0] = '\0';
                char *current_rebuilt_ptr = rebuilt_arg_buffer;
                const char *scan_ptr = arg_after_var_expansion;
		//printf("command word: %s\n", scan_ptr);
                while (*scan_ptr) {
                    char *backtick_start = strchr(scan_ptr, '`');
                    if (backtick_start) {
                        char *backtick_end = strchr(backtick_start + 1, '`');
                        if (backtick_end) {
                            // Copy part before the first backtick
                            if (backtick_start > scan_ptr) {
                                mystrncpy(current_rebuilt_ptr, scan_ptr, backtick_start - scan_ptr);
                                current_rebuilt_ptr += (backtick_start - scan_ptr);
				//printf("rebuilt: %s\n", current_rebuilt_ptr);
                            }
                            // Extract command for substitution
                            char cmd_to_subst[MAX_INPUT_BUF];
                            int cmd_len = backtick_end - (backtick_start + 1);
                            if (cmd_len >= MAX_INPUT_BUF) cmd_len = MAX_INPUT_BUF -1; // Truncate if too long
                            mystrncpy(cmd_to_subst, backtick_start + 1, cmd_len);
                            cmd_to_subst[cmd_len] = '\0';
			    //printf("cmd_to_subst: %s\n", cmd_to_subst);
                            // Execute substitution
                            char *subst_output = execute_command_substitution(cmd_to_subst, parent_shell_is_interactive);
                            if (subst_output) { // subst_output is already processed (newlines stripped/replaced)
                                mystrcat(current_rebuilt_ptr, subst_output); // Append result
                                current_rebuilt_ptr += mystrlen(subst_output);
                            }
                            scan_ptr = backtick_end + 1; // Continue scanning after the closing backtick
                        } else { // Unmatched opening backtick, treat literally
                            mystrcat(current_rebuilt_ptr, scan_ptr);
                            current_rebuilt_ptr += mystrlen(scan_ptr);
                            scan_ptr += mystrlen(scan_ptr); // Go to end
                        }
                    } else { // No more backticks in the remainder of the string
                        mystrcat(current_rebuilt_ptr, scan_ptr);
                        current_rebuilt_ptr += mystrlen(scan_ptr);
                        break; // Done with this argument string
                    }
                }
                *current_rebuilt_ptr = '\0'; // Null terminate the rebuilt argument
                if (rebuilt_arg_buffer[0] != '\0' || arg_after_var_expansion[0] == '\0') { // If something was rebuilt or original was empty
                    final_arg_for_argv = user_strdup(rebuilt_arg_buffer);
                } else { // No substitutions, or only var expansion happened
                    final_arg_for_argv = user_strdup(arg_after_var_expansion); // strdup the var-expanded one
                }
                // --- End Command Substitution Pass ---
                cmd_data->argv[cmd_data->argc++] = final_arg_for_argv;
		//printf("final_arg_for_argv: %s\n", final_arg_for_argv);
            } else { /* ... too many args ... */ return NULL; }
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
```

在解析完AST语法树后，会返回语法树的根节点 ASTNode * node。

之后就进入执行语法树的过程了。执行语法树的过程主要是根据当前ASTNode的类型来进行不同的操作。

如果当前是NODE_COMMAND，则利用当前节点包含的command来运行指令。运行的过程为，先判断该指令是否是内部指令，如果是的话直接调用函数运行，否则用spawn创建子进程运行。

如果当前是NODE_PIPELINE，则先创建管道，之后新开两个子进程，分别运行管道左右两边的命令。运行左边的命令时，将标准输出与管道的写端共享页面，即往标准输出的写入被视为写入管道；运行右边的命令时，将标准输入与管道的读端共享页面，即从标准输入的读取被视为读取管道。这样执行右边命令的进程在读取时，读取到的就是执行左边命令的进程的输出，也就是完成管道的作用。

如果是NODE_AND或者NODE_OR，则先递归运行左边的命令，之后根据管道来传输运行返回值，再根据条件运行的条件判断来确定是否运行右边的指令。

如果是NODE_LIST_SEMI，则是多条指令在同一行运行的情况。只需要按顺序依次从左到右运行指令即可。

总体代码如下：

```C
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
	    //printf("%s is outer command\n", cmd->argv[0]);
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
			int i=0;
			printf("");
			char **argv2 = (char **)cmd->argv;
			while(argv2[i] != NULL) {
				printf("",argv2[i++]);
			}
			printf("");
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
            if (node->data.binary_op.right && mystrcmp(node->data.binary_op.left->data.command.argv[0], "/mkdir") != 0) {
                 execute_ast(node->data.binary_op.right);
            }
            break;
        case NODE_OR: 
            // TODO: Proper exit status handling needed
            execute_ast(node->data.binary_op.left);
            // For now, simplified: always execute right if it exists
            if (node->data.binary_op.right  && mystrcmp(node->data.binary_op.left->data.command.argv[0], "/mkdir") == 0) {
                execute_ast(node->data.binary_op.right);
            }
            break;
        
        default:
            user_panic("Unknown AST node type: %d", node->type);
    }
}
```

到此，我重构的AST语法树结构就基本完成了，下面开始新增指令运行。
#### 不带 `.b` 后缀指令

你需要实现不带 `.b` 后缀的指令，但仍需兼容带有 `.b` 后缀的指令，如 `ls` 与 `ls.b` 都应能够正确列出当前目录下的文件。
只需要在第一次打开文件失败后手动在prog后面添加 .b 字符再次尝试打开即可。

![[8de0e16902ecb80c04368d073a6e7df.png]]
![[d28d4347f8d3f3152a9c1b2f2ea52d8.png]]

#### 实现注释功能

你需要使用 `#` 实现注释功能，例如 `ls | cat # this is a comment meow`，`ls | cat` 会被正确执行，而后面的注释则会被抛弃
当解析输出读取到#时，会之间移动到输入的末尾，期间的内容不会被解析

![[c9c2b27830553cf18c139f983108d76.png]]
### 支持相对路径

MOS 中现有的文件系统操作并不支持相对路径，对于一切路径都从根目录开始查找，因此在 shell 命令中也需要用绝对路径指代文件，这为命令的描述带来了不便。你需要为每个进程维护**工作目录**这一状态，实现相关内建指令，并为其他与路径相关的指令提供路径支持。

首先，为了让进程维护自己的工作路径，需要在进程控制块中加入工作路径这一成员。

![[66e2196248e68bc4e3e903cb75f3048.png]]

然后在创建进程的时候，默认将进程的cwd初始化为根目录。也就是当shell被创建的时候所在的默认目录。要时刻保证进程的工作路径与实际所在路径一致。

![[367480acc3337a687cad2f967d176dc.png]]

之后在进行sys_exofork系统调用的时候，将新申请的进程的cwd赋值为父进程的cwd。这样做是因为，子进程是父进程创建出来的，因此子进程所在的工作路径应该与父进程保持一致，这样执行外部指令时，采用相对地址才能保持一致。

![[9b60fd5aec9ad1c3dd0110a486d74dd.png]]

然后编写两个系统调用：sys_get_cwd, sys_set_cwd，分别用来获得和更新当前进程的cwd。
之后由于cd、pwd是内部指令，因此其应当由shell进程执行，具体过程为在shell进程中编写函数，执行cd和pwd的相关行为。

先判断当前指令是否是cd或者pwd，如果是的话，进入内部命令执行函数。如果当前指令是pwd，则直接输出当前工作路径即可。如果是cd，那么如果按照题目要求实现。

代码如下：

```C
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
    	} else if (mystrcmp(cmd->argv[0], "history") == 0) {
 		if (cmd->argc > 1) {
        		printf("history: too many arguments\n");
        		return; // Or return an error code for builtins
    		}
    		int start_idx;
    		if (history_count == 0) {
        		return; // Nothing to print
    		}
    		if (history_count < HISTFILESIZE) {
        		start_idx = 0;
    		} else {
        		start_idx = history_add_idx; // Oldest is where next add would go
    		}
    		for (int i = 0; i < history_count; ++i) {
        		int current_entry_idx = (start_idx + i) % HISTFILESIZE;
        		// Bash history usually prints with line numbers. For MOS, just the command.
        		printf("%s\n", history_lines[current_entry_idx]);
    		}
	}
}
```

其中的关键是利用当前工作路径和传入的路径参数计算绝对路径，函数如下：

核心思路是先检验传入的path开头是否是/，如果是说明传入的就是绝对路径，那么直接使用即可，如果不是说明是绝对路径，此时需要进行拼接。进行拼接的操作是，先将当前工作路径和传入的相对路径进行字符串拼接，之后进行路径标准化。

路径标准化的方式是，遇到./可以去掉，遇到../则去掉上一级目录，如果没有上一级则保留根目录。

```C
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
```

最后，由于外部指令也需要实现相对路径，因此要确保外部指令在open的时候能够正确打开绝对路径。因此需要改写open函数，在open刚开始的时候，需要先获取当前工作路径并进行路径拼接，之后再利用拼接好的绝对路径来在磁盘中访问文件。

#### 环境变量管理

MOS 中的Shell目前并不支持环境变量,你需要在shell中增加对环境变量的支持。

规定环境变量在命令中以`$`开头，名称与C语言变量命名要求，且长度不超过16，环境变量的值长度同样不超过16。环境变量可分为局部变量与非局部变量，仅非局部变量可传入子Shell中，并且只有非只读变量可被修改。

**核心数据结构与变量:**

- **ShellVar shell_vars\[MAX_SHELL_VARS];**: 这是实现环境变量管理的核心。它是一个结构体数组，每个 ShellVar 结构体代表一个变量。
    
    - name\[MAX_VAR_NAME_LEN + 1]: 变量名。
        
    - value\[MAX_VAR_VALUE_LEN + 1]: 变量值。
        
    - is_exported: 一个标志，表示变量是否为环境变量（非局部变量）。1 表示是环境变量，0 表示是局部变量。
        
    - is_readonly: 一个标志，表示变量是否为只读。1 表示只读，0 表示可写。
        
    - is_set: 一个标志，表示该 ShellVar 槽是否被使用（即是否设置了变量）。
        
- **num_set_vars**: 记录当前已设置的变量数量，用于快速判断是否满了。
    
- **expansion_buffer_pool 和 expansion_buffer_pool_index**: 用于存储变量展开后的临时结果。get_expansion_buffer 函数从池中获取一个缓冲区供 expand_string_variables 使用。
    

**实现的功能与对应代码分析:**

1. **变量创建与查找 (find_variable, find_free_slot, set_variable)**
    
    - **find_variable(const char *name)**:
        
        - 遍历 shell_vars 数组。
            
        - 如果找到一个槽 is_set 为 1 且 name 与输入 name 相符，则返回指向该 ShellVar 结构体的指针。
            
        - 否则返回 NULL。
            
    - **find_free_slot()**:
        
        - 遍历 shell_vars 数组，寻找第一个 is_set 为 0 的槽。
            
        - 返回指向该空槽的指针。如果所有槽都已使用，返回 NULL。
            
    - **set_variable(const char *name, const char *value, int export_flag, int readonly_flag, int update_flags_if_exists)**:
        
        - **名称和值长度检查**: 检查 name 和 value 的长度是否超过 MAX_VAR_NAME_LEN 和 MAX_VAR_VALUE_LEN。
            
        - **查找变量**: 首先调用 find_variable 检查变量是否已存在。
            
        - **修改现有变量**:
            
            - 如果变量存在且是只读的 (var->is_readonly == 1)，则不允许修改，打印错误信息并返回 -1。
                
            - 如果变量存在且可写，则更新其 value。
                
            - 如果 update_flags_if_exists 为真，则更新 is_exported 和 is_readonly 标志。注意，这里只允许将变量设置为只读，不能从只读变为可写（因为上面的 is_readonly 检查已经捕获了尝试修改只读变量值的情况）。
                
        - **创建新变量**:
            
            - 如果变量不存在，则调用 find_free_slot 寻找空槽。
                
            - 如果找到空槽，则填充 name、value、is_exported、is_readonly，并将 is_set 设置为 1。
                
            - num_set_vars 递增。
                
            - 如果找不到空槽，打印错误信息并返回 -1。
                
2. **变量删除 (unset_variable)**
    
    - **unset_variable(const char *name)**:
        
        - 调用 find_variable 查找变量。
            
        - 如果变量不存在，打印错误信息并返回 -1。
            
        - 如果变量存在但 is_readonly 为 1，打印错误信息（不可删除只读变量）并返回 -1。
            
        - 如果变量存在且可删除，则将其 is_set 设置为 0，清空 name（方便 find_free_slot），并递减 num_set_vars。
            
3. **显示所有变量 (print_all_variables)**
    
    - **print_all_variables()**:
        
        - 遍历 shell_vars 数组。
        - 对于每个 is_set 为 1 的变量，按照 \<var>=\<val> 的格式打印其 name 和 value。
        
4. **变量展开 (expand_string_variables, get_variable_value)**
    
    - **get_variable_value(const char \*name)**:
        
        - 非常简单：查找变量，如果找到并已设置，返回其 value 指针；否则返回 NULL。
            
    - **expand_string_variables(char *input_str)**:
        
        - 这是处理 $VAR 语法的核心。
            
        - **检查是否有 '
            
            ```
            ′∗∗:如果输入字符串中没有‘′∗∗:如果输入字符串中没有‘
            ```
            
            `，直接复制一份原字符串并返回（避免修改原始字符串，并从池中分配）。
            
        - **逐字符扫描**:
            
            - 遇到 $ 时：
                
                - 跳过 $。
                    
                - **解析变量名**: 从 $ 后开始，读取符合变量命名规则的字符（这里允许字母、数字、下划线，直到遇到空格、$、操作符或字符串结束，且不超过 MAX_VAR_NAME_LEN）。
                    
                - **查找变量值**: 调用 get_variable_value 获取变量名对应的值。
                    
                - **追加到输出**: 如果找到变量值，将其追加到输出缓冲区。如果变量不存在，则什么也不追加（相当于展开为空）。
                    
                - **处理单个 $**: 如果 $ 后没有有效变量名（例如 \$$ 或 $ 后面紧跟分隔符），则将 $ 字面量添加到输出。
                    
            - 遇到非 $ 字符时：
                
                - 直接将其追加到输出缓冲区。
                    
        - **缓冲区管理**: 使用 get_expansion_buffer() 从池中获取缓冲区，并检查是否会溢出 MAX_EXPANDED_STR_LEN。
            
        - **结果返回**: 返回一个指向已展开字符串的指针（在 expansion_buffer_pool 中）。
            
5. **环境变量继承与子 Shell (main 函数中 spawn 相关的部分, execute_ast 中 NODE_COMMAND 的 child 进程部分)**
    
    - **main 函数 (处理传递给 sh.b 的参数)**:
        
        - 在 main 函数的开头，当解析到参数列表时，代码遍历 argv。
            
        - 它检查形如 NAME=VALUE 的参数，并将其视为从父 Shell 传递过来的环境变量。
            
        - 对于这些参数，它会解析出 NAME 和 VALUE，并调用 set_variable 将它们设置为**环境变量** (is_exported = 1)，并且**不是只读** (is_readonly = 0，除非参数以 '1' 开头，但这个逻辑不太符合标准环境变量传递方式，可能是特定实现)。
            
    - **execute_ast (处理 NODE_COMMAND)**:
        
        - 当执行一个 NODE_COMMAND 节点时，如果是执行 sh.b 或 sh 命令本身：
            
            - 它会准备一个 spawn_argv 数组。
                
            - 首先复制命令和它的参数。
                
            - 然后，它遍历 shell_vars 数组，查找所有 is_exported 为 1 的变量。
                
            - 对于每一个导出的环境变量，它会构建一个 "NAME=VALUE" 的字符串（**这里有一个小问题，代码中 env_str_pool 的构建逻辑似乎是 strcat(current_env_str, "1"); 然后 strcat(current_env_str, shell_vars[i].name); ... 看起来像是把 is_readonly 标志放在了环境变量字符串的开头，这可能不是标准方式，标准是直接传 NAME=VALUE，父进程的 envp 数组包含这些。但对于子 shell 的 spawn 函数来说，只要它能正确解析，就可以工作。**）。
                
            - 将这些 "NAME=VALUE" 字符串添加到 spawn_argv 中，最后以 NULL 结束。
                
            - 最后调用 spawn(cmd->argv\[0], spawn_argv)，这将创建一个子进程，并将这些环境变量作为子进程的环境传递（通常 spawn 函数会处理 argv 的格式来设置子进程的环境）。
                

**总结实现情况:**

- **环境变量管理 (局部/环境变量, 读写性)**: **已实现**。通过 ShellVar 结构体的 is_exported 和 is_readonly 标志以及 set_variable 函数来管理。
    
- **declare 内建指令**: **已实现**。
    
    - 支持 -x (is_exported) 和 -r (is_readonly) 标志。
        
    - 支持 NAME\[=VALUE] 格式的设置。
        
    - 支持缺省 VALUE 为空字符串。
        
    - 支持只输入 declare 显示所有变量。
        
    - **注意**: 对于 declare 输出所有变量部分，它只打印 name=value，没有显示 export 或 readonly 标记。
        
- **unset 内建指令**: **已实现**。
    
    - 支持删除非只读变量。
        
    - 对只读变量的操作会报错。
        
- **变量展开 ($NAME)**: **已实现**。在 expand_string_variables 函数中完成，能够处理 $VAR，并从环境变量池中取值。支持对文件名和命令参数中的变量进行展开。
    
- **环境变量继承**: **已实现**。在子 Shell (sh.b) 启动时，将导出的变量以 NAME=VALUE 的形式传递给 spawn 函数。
    
- **子 Shell 修改环境变量不影响父 Shell**: **已实现**。当子 Shell 修改或添加其自己的变量时，这些修改只发生在子 Shell 的进程空间内，不会影响父 Shell 的 shell_vars 数组。父 Shell 在执行完子进程后（通过 wait）继续自己的 shell_vars。
    
- **只读变量的修改和删除限制**: **已实现**。在 set_variable 和 unset_variable 中都有相应的检查。
    

**潜在的改进或注意事项:**

- **declare 输出格式**: print_all_variables 可以修改以更像 bash，显示 export 和 readonly 等修饰符。

#### 指令自由输入

现有的 shell 不支持在输入命令时移动光标。你需要实现：键入命令时，可以使用 Left 和 Right 移动光标位置，并可以在当前光标位置进行字符的增加与删除。要求每次在不同位置键入后，可以完整回显修改后的命令，并且键入回车后可以正常运行修改后的命令。

**实现机制分析:**

1. **缓冲区与光标管理:**
    
    - buf: 存储用户当前输入的命令字符串。
        
    - n: buf 的总大小。
        
    - current_len: 当前 buf 中已输入的字符数量。
        
    - cursor_pos: 当前光标在 buf 中的位置（从 0 开始，表示在第一个字符之前）。
        
    - onscreen_cmd_len: 记录了上次在屏幕上显示了多少个命令字符。这对于正确地擦除旧内容（通过打印空格）和定位光标非常重要。
        
2. **按键读取与分类:**
    
    - read(0, &c, 1): 这是核心的输入读取操作，每次读取一个字节（一个字符）。
        
    - **特殊字符处理**: 代码对各种按键进行了分类处理：
        
        - **0x1b (ESC 序列)**: 用于处理方向键 (Left, Right, Up, Down) 和其他特殊组合键。
            
            - 读取完 ESC (0x1b) 后，会尝试读取接下来的两个字符 (seq[0], seq[1]) 来识别具体的控制序列。
                
            - seq[1] == 'A' (Up Arrow): 触发历史记录向上浏览（后面会详细讲）。
                
            - seq[1] == 'B' (Down Arrow): 触发历史记录向下浏览。
                
            - seq[1] == 'D' (Left Arrow): 将 cursor_pos 减 1，如果 cursor_pos > 0。
                
            - seq[1] == 'C' (Right Arrow): 将 cursor_pos 加 1，如果 cursor_pos < current_len。
                
        - **\b 或 0x7f (Backspace/Delete)**:
            
            - 如果光标不在行首 (cursor_pos > 0)：
                
                - 使用 mymemmove 将光标位置后的所有字符向前移动一位，覆盖掉被删除的字符。
                    
                - current_len 减 1。
                    
                - cursor_pos 减 1。
                    
                - 设置 requires_full_reprint = 1 以便重新绘制。
                    
        - **\r 或 \n (回车)**:
            
            - 表示命令输入完成。
                
            - 将 buf 的当前内容保存到 current_typed_line（用于下次输入时恢复）。
                
            - 调用 add_to_history 和 save_history。
                
            - 返回 readline 函数，将 buf 的内容传递给解析器。
                
        - **可打印字符 ( c >= 0x20 && c < 0x7f)**:
            
            - 如果光标不在行尾 (cursor_pos < current_len)：
                
                - 使用 mymemmove 将光标位置及之后的字符向后移动一位，为新字符腾出空间。
                    
            - 将新字符 c 插入到 buf[cursor_pos]。
                
            - current_len 加 1。
                
            - cursor_pos 加 1。
                
            - 设置 requires_full_reprint = 1。
                
        - **其他特殊控制键**: 代码还处理了一些常见的编辑组合键，如 Ctrl+A (移到行首), Ctrl+E (移到行尾), Ctrl+K (剪切到行尾), Ctrl+U (剪切到行首), Ctrl+W (删除一个词)。这些功能也依赖于 cursor_pos 和 mymemmove 来修改 buf。
            
3. **完整回显 (requires_full_reprint 和屏幕刷新逻辑)**:
    
    - 每当输入导致 buf 内容发生变化（插入、删除、移动光标）时，requires_full_reprint 标志会被设置为 1。
        
    - 在每次循环的结尾，如果 requires_full_reprint 为真并且 interactive 为真：
        
        - **printf("\r");**: 将光标移动到当前行的开头。
            
        - **printf("$ ");**: 重新打印提示符。
            
        - **打印命令内容**: 遍历 buf 中当前长度的字符并打印出来。
            
        - **擦除多余字符**: 如果当前输入的命令比上次显示的内容短 (current_len < onscreen_cmd_len)，则需要打印空格来覆盖掉旧的（现在不存在的）字符。
            
        - **定位光标**:
            
            - effective_displayed_cmd_len 用于计算当前行实际显示了多少字符（包括提示符后的命令部分）。
                
            - for (u_int i = 0; i < (effective_displayed_cmd_len - cursor_pos); ++i) { printf("\b"); }: 这是一个关键的回显技巧。它通过打印 \b (退格符) 来将光标移动到正确的位置。例如，如果命令是 ls -l，onscreen_cmd_len 是 4，current_len 是 3，cursor_pos 是 1 (在 l 和 - 之间)，那么需要回退 (4 - 1) = 3 步，才能回到新内容的正确位置。
                
        - **onscreen_cmd_len = current_len;**: 更新 onscreen_cmd_len 以便下次回显时知道屏幕上显示了多少内容。
            
4. **与历史记录的集成 (history_current_nav_offset, current_typed_line)**:
    
    - history_current_nav_offset: 当用户按下向上或向下箭头时，这个变量用于跟踪用户在历史记录中的位置。0 表示当前正在输入的行；1 表示上一条历史记录；2 表示上两条历史记录，依此类推。
        
    - current_typed_line: 当用户从历史记录中选择一条命令并开始编辑它时，readline 会将当前输入的 buf 内容复制到 current_typed_line。这使得用户可以“退出”历史记录浏览模式，回到编辑当前输入行。
        
    - **历史记录浏览**:
        
        - 当按下向上箭头 (seq[1] == 'A')：
            
            - 如果用户正在编辑新行 (history_current_nav_offset == 0)，先将当前输入的内容保存到 current_typed_line。
                
            - 如果还有更早的历史记录可供访问 (history_current_nav_offset < history_count)，则 history_current_nav_offset 增加。
                
            - 根据新的 history_current_nav_offset 从 history_lines 数组中计算出要显示的旧命令（利用了循环缓冲区索引的计算）。
                
            - 将该历史命令复制到 buf，更新 current_len 和 cursor_pos，并设置 requires_full_reprint = 1。
                
        - 当按下向下箭头 (seq[1] == 'B')：
            
            - 如果 history_current_nav_offset > 0，则 history_current_nav_offset 减小。
                
            - 如果 history_current_nav_offset 变为了 0，表示用户回到了最初的 current_typed_line，此时将 current_typed_line 的内容复制回 buf。
                
            - 否则，从历史记录中加载旧命令，更新 buf 和相关变量，并重绘。
                

**总结实现细节:**

- **光标移动**: 通过精确控制 cursor_pos 变量，并在每次改动后使用退格符 \b 来重定位光标，实现左右光标移动。
    
- **字符插入**: 使用 mymemmove 将光标后的内容后移，腾出空间，然后在 buf[cursor_pos] 插入字符。
    
- **字符删除**: 使用 mymemmove 将光标后的内容前移，覆盖被删除字符。
    
- **完整回显**: 通过 onscreen_cmd_len 和 requires_full_reprint 标志，在每次输入改动后，重新绘制整个命令行的内容，并精确地将光标放回正确位置。这保证了用户看到的是一个连续的、正确的编辑界面。
    
- **历史记录集成**: 通过 history_current_nav_offset 和 current_typed_line 实现了在输入行和历史记录之间的切换和编辑。

#### 快捷键

你需要在Shell中实现以下快捷键:
快捷键行为:
left-arrow    光标尝试向左移动，如果可以移动则移动
right-arrow    光标尝试向右移动，如果可以移动则移动
backspace    删除光标左侧 1 个字符并将光标向左移动 1 列；若已在行首则无动作
Ctrl-E    光标跳至最后
Ctrl-A    光标跳至最前
Ctrl-K    删除从当前光标处到最后的文本
Ctrl-U    删除从最开始到光标前的文本
Ctrl-W    向左删除最近一个 word：先越过空白(如果有)，再删除连续非空白字符

**核心函数: readline(char *buf, u_int n, int interactive)**

这个函数是处理所有用户输入的入口，它负责识别按键，执行相应的操作，并在必要时更新屏幕显示。

**快捷键实现分析:**

1. **光标移动 (Left/Right Arrow)**
    
    - **触发条件**: c == 0x1b (ESC), seq[0] == '[', seq[1] == 'D' (Left) 或 'C' (Right)。
        
    - **Left Arrow (seq[1] == 'D')**:
        
        - 检查 cursor_pos > 0。
            
        - 如果条件为真，则 cursor_pos--。
            
        - 设置 requires_full_reprint = 1，表示屏幕需要重绘以反映光标位置的变化。
            
    - **Right Arrow (seq[1] == 'C')**:
        
        - 检查 cursor_pos < current_len。
            
        - 如果条件为真，则 cursor_pos++。
            
        - 设置 requires_full_reprint = 1。
            
    - **回显更新**: requires_full_reprint 标志会在循环末尾触发屏幕重绘，根据新的 cursor_pos 定位光标，确保用户看到正确的显示。
        
2. **Backspace (删除光标左侧字符)**
    
    - **触发条件**: c == '\b' 或 c == 0x7f (通常是 Backspace 或 Delete 键)。
        
    - **逻辑**:
        
        - 首先检查 history_current_nav_offset != 0。如果用户正在浏览历史记录，按下 Backspace 会将其从历史记录模式切换回正常编辑模式，并将当前显示的历史记录复制到 current_typed_line。这是一个重要的 UX 考虑。
            
        - 检查 cursor_pos > 0 (确保不在行首)。
            
        - 如果光标不在行首：
            
            - mymemmove(&buf[cursor_pos - 1], &buf[cursor_pos], current_len - cursor_pos + 1): 这是核心操作。它将光标位置 cursor_pos 处的字符（包括光标本身）以及之后的所有字符，向前移动一个位置。这effectively抹去了光标左侧的字符。
                
            - cursor_pos--: 光标位置随之向左移动一位。
                
            - current_len--: 输入的字符总数减少一个。
                
            - 设置 requires_full_reprint = 1。
                
    - **行首处理**: 如果 cursor_pos == 0，则 Backspace 键被忽略，不做任何操作。
        
3. **Ctrl-E (光标跳至最后)**
    
    - **触发条件**: c == 0x05 (Ctrl-E 的 ASCII 值)。
        
    - **逻辑**:
        
        - 检查 cursor_pos != current_len。
            
        - 如果光标不在行尾，则 cursor_pos = current_len。
            
        - 设置 requires_full_reprint = 1。
            
    - **回显更新**: 重绘时，光标会直接定位到行尾。
        
4. **Ctrl-A (光标跳至最前)**
    
    - **触发条件**: c == 0x01 (Ctrl-A 的 ASCII 值)。
        
    - **逻辑**:
        
        - 检查 cursor_pos != 0。
            
        - 如果光标不在行首，则 cursor_pos = 0。
            
        - 设置 requires_full_reprint = 1。
            
    - **回显更新**: 重绘时，光标会直接定位到行首。
        
5. **Ctrl-K (删除从当前光标处到最后的文本)**
    
    - **触发条件**: c == 0x0B (Ctrl-K 的 ASCII 值)。
        
    - **逻辑**:
        
        - 首先，检查用户是否在浏览历史记录，如果是，则将其切换到正常编辑模式（同 Backspace）。
            
        - 检查 cursor_pos < current_len。
            
        - 如果光标不在行尾（即有文本可删）：
            
            - buf[cursor_pos] = '\0';: 在当前光标位置直接截断字符串，将该位置之后的所有内容视为无效。
                
            - current_len = cursor_pos;: 更新当前字符串长度为光标位置。
                
            - 设置 requires_full_reprint = 1。
                
    - **回显更新**: 重绘时，只会显示从行首到新 current_len 的内容。
        
6. **Ctrl-U (删除从最开始到光标前的文本)**
    
    - **触发条件**: c == 0x15 (Ctrl-U 的 ASCII 值)。
        
    - **逻辑**:
        
        - 首先，检查用户是否在浏览历史记录，如果是，则将其切换到正常编辑模式。
            
        - 检查 cursor_pos > 0。
            
        - 如果光标不在行首（即有文本可删）：
            
            - mymemmove(&buf[0], &buf[cursor_pos], current_len - cursor_pos + 1);: 这是核心操作。它将光标位置 cursor_pos 开始的所有字符（包括光标位置后的文本），移动到缓冲区的开头 (buf[0])。这 effectively 丢弃了光标之前（包括光标位置前的）的所有字符。
                
            - current_len -= cursor_pos;: 更新当前字符串长度，减去被删除的字符数量。
                
            - cursor_pos = 0;: 光标被重置到行首，因为所有内容都从那里开始显示了。
                
            - 设置 requires_full_reprint = 1。
                
    - **回显更新**: 重绘时，从 buf[0] 开始显示，并且光标定位在行首。
        
7. **Ctrl-W (向左删除最近一个 word)**
    
    - **触发条件**: c == 0x17 (Ctrl-W 的 ASCII 值)。
        
    - **逻辑**:
        
        - 首先，检查用户是否在浏览历史记录，如果是，则将其切换到正常编辑模式。
            
        - **查找删除范围**:
            
            - original_cursor_pos = cursor_pos;: 保存当前光标位置，以便后续处理。
                
            - **越过尾部空白**: 从 cursor_pos 开始，向前查找第一个非空白字符 (while (cursor_pos > 0 && strchr(" \t", buf[cursor_pos - 1])) cursor_pos--;)。这一步是为了处理用户可能在词后输入了空格的情况。
                
            - end_of_deletion_span = cursor_pos;: 记录当前光标位置（即词的末尾，或尾部空白的起始位置）。
                
            - **查找词的起始**: 从 cursor_pos 开始，向前查找第一个空白字符 (while (start_of_word_to_delete > 0 && !strchr(" \t", buf[start_of_word_to_delete - 1])) { start_of_word_to_delete--; })。这会找到词（或词前面空白串）的起始位置。
                
        - **执行删除**:
            
            - 如果找到了需要删除的有效范围 (start_of_word_to_delete < end_of_deletion_span)：
                
                - mymemmove(&buf[start_of_word_to_delete], &buf[end_of_deletion_span], current_len - end_of_deletion_span + 1);: 将词（和它前面的空白）之后的文本移动到词的起始位置，覆盖掉词及其前面的空白。
                    
                - current_len -= (end_of_deletion_span - start_of_word_to_delete);: 更新总长度。
                    
                - cursor_pos = start_of_word_to_delete;: 将光标定位到删除区域的起始位置。
                    
                - 设置 requires_full_reprint = 1。
                    
            - 如果未找到有效删除范围（例如在行首或者只有空白），光标会回到 original_cursor_pos（基本上无变化）。
                
    - **回显更新**: 重绘时，显示被修改后的 buf，并将光标定位到删除词的起始位置。
        

**回显更新逻辑的关键点:**

requires_full_reprint 配合 onscreen_cmd_len 和退格符 \b 是实现精确回显的关键。当需要更新屏幕时：

1. 移动光标到行首 (\r)。
    
2. 重绘提示符 ($)。
    
3. 打印新的命令内容。
    
4. 如果新内容比旧内容短，则打印足够多的空格来“擦除”旧内容中多余的部分。
    
5. 关键是根据新光标位置，通过连续打印 \b 来将光标准确地放回显示内容的正确位置。

#### 历史指令

你需要实现 shell 中保存历史指令的功能，可以通过 Up 和 Down 选择所保存的指令并执行。你需要将历史指令保存到根目录的 `.mos_history` 文件中（一条指令一行），为了评测的方便，我们设定 `$HISTFILESIZE=20`（bash 中默认为 500），即在 `.mos_history` 中至多保存最近的 20 条指令。你还需要支持通过 `history` 命令输出 `.mos_history` 文件中的内容。

**核心数据结构与变量:**

- **HISTFILESIZE 20**: 定义了历史记录文件和内存中最多保存的指令条数。
    
- **HISTORY_FILE "/.mos_history"**: 定义了存储历史记录的文件路径。
    
- **char history_lines[HISTFILESIZE][MAX_INPUT_BUF]**: 这是一个二维字符数组，用于在内存中存储历史指令。它被实现为一个**循环缓冲区**。
    
- **int history_count = 0;**: 当前内存中实际存储的历史指令条数。
    
- **int history_add_idx = 0;**: 在循环缓冲区中，下一个要添加的新指令的索引。当缓冲区满时，这个索引会指向最旧的那个指令，新指令会覆盖它。
    
- **int history_latest_idx = -1;**: 在循环缓冲区中，最近添加的指令的索引。-1 表示历史记录为空。
    
- **int history_current_nav_offset = 0;**: 用户在浏览历史记录时的偏移量。
    
    - 0: 表示用户当前正在输入新的命令，或者已经回到了输入的新命令。
        
    - 1: 表示用户选择的是上一条历史记录。
        
    - N: 表示用户选择的是第 N 条历史记录。
        
- **char current_typed_line[MAX_INPUT_BUF] = {0};**: 用于暂存用户在浏览历史记录时（按下 Up Arrow）之前输入的、未提交的命令。当用户按下 Down Arrow 并且 history_current_nav_offset 变为 0 时，会从这里恢复。
    

**实现的功能与对应代码分析:**

1. **加载历史记录 (load_history())**
    
    - **目的**: Shell 启动时，从 HISTORY_FILE 读取最近 HISTFILESIZE 条指令到内存中的 history_lines。
        
    - **逻辑**:
        
        - 打开 HISTORY_FILE (只读 O_RDONLY)。如果文件不存在或无法打开，则静默失败（不加载历史）。
            
        - 逐行读取文件内容到 line_buf。
            
        - 使用一个临时缓冲区 temp_history_load 来存储从文件读取的行。
            
        - **循环缓冲区填充逻辑**:
            
            - 如果 temp_count (临时缓冲区中的条数) 小于 HISTFILESIZE，则直接添加到 temp_history_load。
                
            - 如果 temp_count 达到 HISTFILESIZE，则在添加新行之前，将 temp_history_load 中的所有旧条目向前移动一位，覆盖掉最旧的条目，然后将新行添加到最后。这是一个模拟循环缓冲区的策略。
                
        - 文件读取完毕后，将 temp_history_load 中的内容按照正确的顺序（从旧到新）复制到实际的 history_lines 循环缓冲区中，并更新 history_add_idx 和 history_latest_idx。
            
        - 最后，将 history_current_nav_offset 重置为 0。
            
2. **保存历史记录 (save_history())**
    
    - **目的**: Shell 退出时，将内存中的 history_lines（最新的 HISTFILESIZE 条）写回 HISTORY_FILE。
        
    - **逻辑**:
        
        - 打开 HISTORY_FILE (写模式 O_WRONLY，创建 O_CREAT，截断 O_TRUNC)。如果打开失败则打印错误。
            
        - 根据 history_count 和 history_add_idx 确定历史记录的起始索引 (start_idx)。如果历史记录未满 (history_count < HISTFILESIZE)，则从索引 0 开始；如果已满或溢出，则从 history_add_idx 开始（这是最旧的记录）。
            
        - 从 start_idx 开始，循环 history_count 次，将 history_lines[current_entry_idx] 的内容和换行符写入文件。
            
        - 关闭文件。
            
3. **添加指令到历史记录 (add_to_history(const char *cmd_line))**
    
    - **目的**: 在用户执行一条指令后，将其添加到内存中的历史记录。
        
    - **逻辑**:
        
        - 忽略空命令。
            
        - **去重**: 检查新命令是否与最后一条历史记录相同。如果相同，则不添加，避免重复项。
            
        - 将新命令 cmd_line 复制到 history_lines[history_add_idx]。
            
        - 更新 history_latest_idx = history_add_idx。
            
        - 更新 history_add_idx = (history_add_idx + 1) % HISTFILESIZE，移动到下一个可用位置。
            
        - 如果 history_count < HISTFILESIZE，则 history_count++，表示记录数增加。
            
        - **重置导航状态**: history_current_nav_offset = 0，表示用户回到了当前输入的行，而不是在浏览历史记录。
            
4. **使用 Up/Down Arrow 选择历史记录 (在 readline 函数中)**
    
    - **触发条件**: 读取到 ESC 序列，并且是 '[' 后面跟着 'A' (Up) 或 'B' (Down)。
        
    - **Up Arrow (seq[1] == 'A')**:
        
        - 首先，如果用户当前正在编辑新行 (history_current_nav_offset == 0)，则将 buf 的内容保存到 current_typed_line，为稍后恢复输入提供基础。
            
        - 检查 history_current_nav_offset < history_count。这确保了我们不会越过最早的记录。
            
        - 如果可以向上浏览：
            
            - history_current_nav_offset++。
                
            - 根据新的 history_current_nav_offset 和 history_latest_idx 计算出要加载的历史记录在 history_lines 数组中的实际索引 (nav_idx_in_hist_array)。
                
            - 将该历史记录复制到 buf，更新 current_len 和 cursor_pos。
                
            - 设置 requires_full_reprint = 1 以更新屏幕显示。
                
    - **Down Arrow (seq[1] == 'B')**:
        
        - 检查 history_current_nav_offset > 0。这确保了我们不会越过当前输入的行。
            
        - 如果可以向下浏览：
            
            - history_current_nav_offset--。
                
            - 如果 history_current_nav_offset == 0，表示用户回到了最初的输入行，将 current_typed_line 的内容复制回 buf。
                
            - 否则（仍然在浏览历史记录），计算要加载的历史记录索引，加载并显示。
                
            - 更新 buf，current_len，cursor_pos，并设置 requires_full_reprint = 1。
                
5. **history 内建命令 (execute_inner_cmd 函数)**
    
    - **触发条件**: 当 execute_ast 检测到 NODE_COMMAND 的第一个参数是 "history" 且没有其他参数时。
        
    - **逻辑**:
        
        - 检查 cmd->argc > 1。如果命令带了除 history 之外的参数，会打印用法错误。
            
        - 如果 history_count == 0，则什么也不做。
            
        - **确定起始打印位置**:
            
            - 如果 history_count < HISTFILESIZE (历史记录未满)，从索引 0 开始打印。
                
            - 如果 history_count >= HISTFILESIZE (历史记录已满或已循环)，则从 history_add_idx 开始打印（因为 history_add_idx 指向的是下一个要添加的位置，也就是最旧的那个元素）。
                
        - **遍历并打印**: 从确定的 start_idx 开始，循环 history_count 次，使用模运算 (% HISTFILESIZE) 来正确地在循环缓冲区中获取和打印每一条历史记录。
            

**与主循环的交互:**

- Shell 的主循环 (main 函数) 在每次迭代开始时：
    
    - 调用 load_history() 加载历史记录。
        
    - 调用 readline() 获取用户输入。
        
    - readline 返回后，将用户的输入（可能经过历史记录选择和编辑）复制到 input_buf。
        
    - 然后调用 add_to_history() 将这条输入的命令添加到内存历史记录中。
        
    - 接着调用 save_history() 将最新的历史记录写回文件。
        

**总结:**

MOS Shell 通过以下方式实现了历史指令功能：

- **内存存储**: 使用一个循环缓冲区 history_lines 在内存中保存最近的 HISTFILESIZE 条指令。
    
- **文件持久化**: 在启动时加载，退出时保存到 .mos_history 文件，确保历史记录的持久性。
    
- **历史记录浏览**: 在 readline 函数中通过解析方向键序列，利用 history_current_nav_offset 来跟踪用户在历史记录中的位置，并动态加载和显示历史命令到输入行。
    
- **编辑与恢复**: 使用 current_typed_line 变量，允许用户在浏览历史记录后编辑选择的命令，并将编辑后的命令作为新的当前输入行处理。
    
- **history 命令**: 实现了一个内建命令，可以方便地查看当前内存中的所有历史指令。

#### 实现反引号

你需要使用反引号实现指令替换。你需要将反引号内指令执行的所有标准输出代替原有指令中的反引号内容。

**关键函数与逻辑:**

1. **识别反引号**:
    
    - 反引号  被识别为一种特殊的 TOKEN_WORD。
        
    - 在 get_next_raw_token() 函数中，当遇到\`时，它会捕获从开头的  到匹配的结尾  的所有内容，并将这个字符串（包括反引号）作为一个 TOKEN_WORD 返回。
        
    - **注意**: 当前的 get_next_raw_token 实现对于反引号的识别很简单，它会把  包裹的内容作为一个单独的 TOKEN_WORD。它**不处理嵌套反引号**，**也不处理反引号内的转义字符**（例如 \ 后面跟着 ）。
        
2. **命令替换的执行 (execute_command_substitution)**
    
    - **被调用时机**: 这个函数在 parse_command() 函数内部被调用。当 parse_command() 处理一个 TOKEN_WORD 时，它会先调用 expand_string_variables 来展开变量，然后对展开后的字符串执行一个**二次扫描**，查找其中的反引号对。
        
    - **get_subst_output_buffer()**: 这个函数从一个预分配的缓冲区池中获取一个空缓冲区，用于存储被替换命令的输出。这限制了同时进行的命令替换的数量和单个替换输出的最大长度。
        
    - **创建管道**: pipe(pipe_fds) 创建一个匿名管道。管道的读端 (pipe_fds[0]) 和写端 (pipe_fds[1]) 会被用来连接父 Shell 和子命令的输出。
        
    - **fork() 子进程**:
        
        - 在父 Shell（即当前 MOS Shell 进程）中 fork() 出一个子进程。
            
        - **子进程**:
            
            - 关闭管道的读端 (pipe_fds[0])。
                
            - **重定向标准输出**: dup(pipe_fds[1], 1) 将子进程的标准输出文件描述符 (1) 重定向到管道的写端 (pipe_fds[1])。
                
            - 关闭原始的管道写端描述符 pipe_fds[1]。
                
            - **执行命令**: 使用 spawn("/sh.b", sh_argv) 来执行一个独立的 sh.b shell 实例，并传递 -c 参数以及反引号内的实际命令字符串 (command_to_run)。这个 sh.b 进程会执行 command_to_run，并且其输出会被重定向到管道的写端。
                
            - 如果 spawn 失败，子进程会打印错误并退出。
                
        - **父进程**:
            
            - 关闭管道的写端 (pipe_fds[1])。
                
            - **读取管道输出**: 在一个循环中，从管道的读端 (pipe_fds[0]) 读取子进程的标准输出。每次读取一个字符 read_char，并将其追加到预先获取的缓冲区 output_buffer 中。
                
            - **缓冲区溢出处理**: 如果输出超出了 MAX_CMD_SUBST_OUTPUT_LEN，则打印截断警告，然后丢弃管道中剩余的所有数据，以允许子进程正常结束。
                
            - 在读取完成后，为 output_buffer 添加 null 终止符。
                
            - 关闭管道的读端 pipe_fds[0]。
                
            - **wait(child_pid_for_sh_c)**: 父进程等待执行 sh -c "..." 的子进程完成。
                
            - **后处理输出**:
                
                - 移除末尾的换行符和回车符。
                    
                - 将内部的换行符和回车符替换为空字符 \0。这个处理方式是将多个换行符替换成多个 \0，然后 mystrcat 会将它们连接起来，最终形成一个由 \0 分隔的字符串。
                    
            - 返回处理后的 output_buffer 指针。
                
3. **在 parse_command 中集成**:
    
    - 当 parse_command 遇到一个 TOKEN_WORD 时，它会首先对 current_token.value 进行**变量展开**（调用 expand_string_variables）。
        
    - 然后，对变量展开后的字符串（存储在 arg_after_var_expansion 中），进行**二次扫描**来处理命令替换。
        
    - **处理反引号**:
        
        - 使用 scan_ptr 遍历字符串。
            
        - 查找第一个反引号  (backtick_start)。
            
        - 查找匹配的第二个反引号  (backtick_end)。
            
        - 如果找到了成对的反引号：
            
            - 将反引号前的部分（scan_ptr 到 backtick_start）复制到 rebuilt_arg_buffer。
                
            - 提取反引号之间的命令字符串 cmd_to_subst。
                
            - 调用 execute_command_substitution(cmd_to_subst, ...) 来执行命令替换。
                
            - 将 execute_command_substitution 返回的（已处理的）输出追加到 rebuilt_arg_buffer。
                
            - 更新 scan_ptr 到 backtick_end + 1，继续扫描。
                
        - 如果只找到开头的反引号但没有匹配的结尾反引号，则将该部分作为字面量处理。
            
        - 如果字符串中没有反引号，则直接将 arg_after_var_expansion 复制到 rebuilt_arg_buffer。
            
    - 最后，将 rebuilt_arg_buffer 中的内容 user_strdup，作为最终的参数传给 cmd_data->argv。
        

**总结实现机制:**

1. **标记**: 反引号被 tokenizer 识别为特殊的 TOKEN_WORD。
    
2. **解析与处理**: parse_command 在处理 TOKEN_WORD 时，先执行变量展开，然后扫描展开后的字符串，查找  对。
    
3. **分离命令**: 反引号内的命令被提取出来。
    
4. **子 Shell 执行**: 创建一个子进程，通过 sh -c "..." 来执行提取出的命令。
    
5. **输出重定向**: 子进程的标准输出被重定向到一个管道。
    
6. **捕获输出**: 父进程从管道中读取子进程的所有输出。
    
7. **后处理**: 输出的换行符被移除或替换，然后成为最终的替换文本。
    
8. **组装参数**: 最终的参数（包含命令替换结果的参数）被构建并传递给命令的执行。
    

**局限性 (基于代码分析):**

- **无嵌套反引号支持**: 如果命令中存在嵌套的反引号（例如 echoecho `date``），当前的实现将无法正确处理，可能会导致错误或意外行为。
    
- **无转义反引号支持**: 如果用户想在反引号内包含字面上的反引号（例如 echoecho a`b``），当前的实现会认为第二个  是结束反引号的标志，导致错误。
    
- **输出缓冲区限制**: MAX_CMD_SUBST_OUTPUT_LEN 和 MAX_CMD_SUBST_BUFFERS 的限制意味着不能执行产生非常大输出或在同一行有太多命令替换的命令。
    
- **换行符处理**: 将内部换行符替换为 \0 是一个特定实现，它会将内部的多行输出合并成一个用 \0 分隔的“单词”，然后可能被 shell 进一步解析。不同的 shell 对此行为有细微差别。

### 指令条件执行

你需要实现 Linux shell 中的 `&&` 与 `||`。 对于 `command1 && command2`，`command2` 被执行当且仅当 `command1` 返回 0；对于 `command1 || command2`，`command2` 被执行当且仅当 `command1` 返回非 0 值。

条件指令与反引号指令执行同理，开子进程并将指令执行的结果通过管道通信，父进程再根据条件符号的类型和返回值来判断是否运行下一个指令。

### 更多指令

你需要实现 `touch`，`mkdir`，`rm` 指令以及内建指令`exit`，只需要考虑如下情形：

- `touch`:

> - `touch <file>`：创建空文件 `file`，若文件存在则放弃创建，正常退出无输出。 若创建文件的父目录不存在则输出 `touch: cannot touch '<file>': No such file or directory`。 例如 `touch nonexistent/dir/a.txt` 时应输出 `touch: cannot touch 'nonexistent/dir/a.txt': No such file or directory`。

- `mkdir`:

> - `mkdir <dir>`：若目录已存在则输出 `mkdir: cannot create directory '<dir>': File exists`，若创建目录的父目录不存在则输出 `mkdir: cannot create directory '<dir>': No such file or directory`，否则正常创建目录。
> - `mkdir -p <dir>`：当使用 `-p` 选项时忽略错误，若目录已存在则直接退出，若创建目录的父目录不存在则递归创建目录。

- `rm`:

> - `rm <file>`：若文件存在则删除 `<file>`，否则输出 `rm: cannot remove '<file>': No such file or directory`。
> - `rm <dir>`：命令行输出: `rm: cannot remove '<dir>': Is a directory`。
> - `rm -r <dir>|<file>`：若文件或文件夹存在则删除，否则输出 `rm: cannot remove '<dir>|<file>': No such file or directory`。
> - `rm -rf <dir>|<file>`：如果对应文件或文件夹存在则删除，否则直接退出。

- （内建指令）`exit`:执行后退出当前shell

注:对于`rm`,`mkdir`,`touch`指令，若成功执行则返回0，否则返回非零值即可。

代码如下：

```C
#include <lib.h>

void touch(char *path) {
    int fd;
    if ((fd = open(path, O_RDONLY)) >= 0) {
        close(fd);
        return;
    }
    fd = open(path, O_CREAT);
    if (fd == -10) {
        printf("touch: cannot touch '%s': No such file or directory\n", path);
    } else if (fd < 0) {
        printf("other error when touch %s, error code is %d\n", path, fd);
    } else {
        close(fd);
    }
    return;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("nothing to touch\n");
    } else {
        for (int i = 1; i < argc; ++i) {
            touch(argv[i]);
        }
    }
    return 0;
}

```

```C
#include <lib.h>

int flag;

void mkdir(char *path) {
    int fd;
    if (flag) {
        if ((fd = open(path, O_RDONLY)) >= 0) {
            close(fd);
            return;
        }
        int i = 0;
        char str[1024];
        for (int i = 0; path[i] != '\0'; ++i) {
            if (path[i] == '/') {
                str[i] = '\0';
                if ((fd = open(path, O_RDONLY)) >= 0) {
                    close(fd);
                } else {
                    break;
                } 
            }
            str[i] = path[i];
        }
        for (; path[i] != '\0'; ++i) {
            if (path[i] == '/') {
                str[i] = '\0';
                fd = open(str, O_MKDIR);
                if (fd >= 0) {
                    close(fd);
                } else {
                    printf("other error when mkdir %s, error code is %d\n", path, fd);
                }
            }
            str[i] = path[i];
        }
        str[i] = '\0';
        fd = open(str, O_MKDIR);
        if (fd >= 0) {
            close(fd);
        } else {
            printf("other error when mkdir %s, error code is %d\n", path, fd);
        }
    } else {
        if ((fd = open(path, O_RDONLY)) >= 0) {
            close(fd);
            printf("mkdir: cannot create directory '%s': File exists\n", path);
            return;
        }
        fd = open(path, O_MKDIR);
        if (fd == -10) {
            printf("mkdir: cannot create directory '%s': No such file or directory\n", path);
        } else if (fd < 0) {
            printf("other error when mkdir %s, error code is %d\n", path, fd);
        } else {
            close(fd);
        }
        return;
    }
}

int main(int argc, char **argv) {
    char s[5] = "-p";
    //printf("receive mkdir command:\n");
    for (int i = 0; i < argc; i++) {
	char *p = argv[i];
	while (*p != '\0') {
		if (*p == ' ') {
			*p = '\0';
		} else {
			p++;
		}
	}
    	//printf("\"%s\"", argv[i]);
    }
    printf("\n");
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], s) == 0) {
            argv[i] = 0;
            flag = 1;
            break;
        }
    }    

    if (argc < 2) {
        printf("nothing to mkdir\n");
    } else {
        for (int i = 1; i < argc; ++i) {
            if (argv[i] == 0) {
                continue;
            }
            mkdir(argv[i]);
        }
    }
    return 0;
}

```

```C
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

```

要注意在rm中，传递的路径必须是绝对路径，因为后续remove调用ipc后的serve_remove中没有用到open，并且文件系统服务进程的工作路径与shell的工作路径不同，没法将相对路径转换成绝对路径，因此必须在rm内部就转换成绝对路径。

exit是内建指令，只需要调用exit()即可。

### 追加重定向

你需要实现 shell 中 `>>` 追加重定向的功能，例如：

`ls >> file1 ls >> file1`

实现追加重定向首先需要新定义一种文件打开方式APPEND，在识别到redirect类型是APPEND时，就把文件打开方式设置为APPEND，之后在serve_open的时候，如果检测到文件打开方式是APPEND时，就把offset设置为size，这样之后再写入文件的时候就会从data+offset的位置开始写入，也就是在文件末尾追加内容。

至此，挑战性任务的所有内容都已经完成，我在此期间收获了很多，也对操作系统有了更加深入的了解！
