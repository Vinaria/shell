#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#define M_SIZE 10000
#define MYSHELL "./myshell"

#define parse_calloc_er "parse: Memory callocation failed"
#define parse_malloc_er "parse: Memory allocation failed"
#define parse_realloc_er "parse: Memory reallocation failed"
#define parse_quotes_er "parse: Double quotes not closed"

#define parse_bracket_bracket_er "parse_bracket: Wrong bracket order"

#define read_s_malloc_er "read_s: Memory allocation failed"
#define read_s_realloc_er "read_s: Memory reallocation failed"

#define exec_cmd_exec_er "exec_cmd: Execution error"
#define exec_cmd_fork_er "exec_cmd: Error in fork()"

#define exec_bracket_bracket_er "exec_bracket: Invalid bracket usage"

#define exec_pipe_exec_er "exec_pipe: Execution error"
#define exec_pipe_fork_er "exec_pipe: Error in fork()"

#define exec_redir_filename_er "exec_redir: Empty file name"

#define execute_fork_er "execute: Error in fork()"

#define main_inval_param_er "main: Invalid parameters"
#define main_file_er "main: Invalid parameters"

#define mycd_access_er "mycd: Failed to access directory"

#define RED "\033[1;31m\0"
#define BLUE "\033[1;36m\0"
#define WHITE "\033[;37m\0"
#define YELLOW "\033[;33m\0"

void write_all(char ** arr);


void print_err(const char * str_er) {
	printf("%s(# > <) %s%s\n", RED, str_er, WHITE);
}


void print_sys(const char * str_sys) {
	printf("%s%s%s\n", YELLOW, str_sys, WHITE);
}


int len_arr(char ** arr) {
	int count;
	for (count = 0; arr[count]; count ++);
	return count;
}


int isin(char * elem, char ** source) {
	for (int i = 0; source[i]; i ++) if (!strcmp(elem, source[i])) return i;
	return -1;
}


char * read_s(FILE * fp){
	int len, k = 0;
	char *str = malloc(sizeof(char) * M_SIZE);
	if (!str) {print_err(read_s_malloc_er); return NULL; };

	while(fgets(str + k, M_SIZE, fp)){
		len = strlen(str);
		if (str[len - 1] != '\n') {
			k = k + M_SIZE - 1;
			str = realloc(str, sizeof(char) * (k + M_SIZE));
			if (!str) {print_err(read_s_realloc_er); return NULL; };
		} else {
			str[len-1] = '\0';
			return str;
		}
	}

	free(str);
	return NULL;
}


void write_all(char ** arr) {
	if (!arr) {printf("empty array\n"); return;}
	for (int i = 0; arr[i]; i ++)
    if (arr[i][0]) printf("%s\n", arr[i]);
		else printf("\\0\n");
	printf("NULL\n");
}


void free_all(char ** arr){
	if (!arr) return;
	for (int i = 0; arr[i]; i ++) free(arr[i]);
	free(arr);
}


char ** parse(char * str) {

	char * s_buf = calloc(strlen(str) + 1, sizeof(char));
	char ** command_arr = malloc(sizeof(char *) * 1);
	if (!command_arr) { print_err(parse_malloc_er); return NULL; }
	int c_arr = 0, flag = 0, dq_flag = 0, i_buf = 0;

	if (!s_buf) { print_err(parse_calloc_er); free(command_arr); return NULL; }

	for (int i = 0; i < strlen(str); ++i) {

		if (str[i] == '"') {                               // met '"'

			if (dq_flag) dq_flag = 0;
			else dq_flag = 1;

			i_buf ++;
			flag = 0;

		} else if (dq_flag) {                               // inside '"'

			s_buf[i - i_buf] = str[i];

		}	else if (str[i] == ' ') {                                                          // met ' '

			flag = 0;

			if ((i > 0) && (str[i - 1] != ' ') && (s_buf[0])) {

				command_arr[c_arr] = s_buf;
				s_buf = calloc(strlen(str) + 1, sizeof(char));
				if (!s_buf) { print_err(parse_calloc_er); free(command_arr); return NULL;}
				c_arr ++;
				command_arr = realloc(command_arr, sizeof(char *) * (c_arr + 1));
				if (!command_arr) { print_err(parse_realloc_er); free(command_arr); return NULL;}

			}
			i_buf = i + 1;

		} else if ((str[i] == '&') || (str[i] == '|') || (str[i] == '>')) {              // met a doubling special symbol

			if (flag) {
				flag = 0;

				if (str[i] == str[i - 1]) {

					if ((i < strlen(str) - 1) && (str[i] == '|') && (str[i + 1] == '|')) {

						i_buf = i;
						command_arr[c_arr] = s_buf;
						s_buf = calloc(strlen(str) + 1, sizeof(char));
						if (!s_buf) { print_err(parse_calloc_er); free(command_arr); return NULL;}
						s_buf[i - i_buf] = str[i];
						flag = 1;

					} else {

						s_buf[i - i_buf] = str[i];
						i_buf = i + 1;
						command_arr[c_arr] = s_buf;
						s_buf = calloc(strlen(str) + 1, sizeof(char));
						if (!s_buf) { print_err(parse_calloc_er); free(command_arr); return NULL;}

					}

				} else {

					i_buf = i;
					command_arr[c_arr] = s_buf;
					s_buf = calloc(strlen(str) + 1, sizeof(char));
					if (!s_buf) { print_err(parse_calloc_er); free(command_arr); return NULL;}
					s_buf[i - i_buf] = str[i];
					s_buf[i - i_buf + 1] = '\0';
					flag = 1;

				}

				c_arr ++;
				command_arr = realloc(command_arr, sizeof(char*) * (c_arr + 1));
				if (!command_arr) { print_err(parse_realloc_er); free(command_arr); return NULL;}

			} else {

				if (s_buf[0] != '\0') {

					i_buf = i;
					command_arr[c_arr] = s_buf;
					s_buf = calloc(strlen(str) + 1, sizeof(char));
					if (!s_buf) { print_err(parse_calloc_er); free(command_arr); return NULL;}
					c_arr ++;
					command_arr = realloc(command_arr, sizeof(char*) * (c_arr + 1));
					if (!command_arr) { print_err(parse_realloc_er); free(command_arr); return NULL;}

				}

				s_buf[i - i_buf] = str[i];
				flag = 1;
			}

		} else if ((str[i] == ';') || (str[i] == '<') || (str[i] == '(') || (str[i] == ')')) {          // met an ordinary special symbol

			if (flag || s_buf[0]) {

				flag = 0;
				i_buf = i;
				command_arr[c_arr] = s_buf;
				s_buf = calloc(strlen(str) + 1, sizeof(char));
				if (!s_buf) { print_err(parse_calloc_er); free(command_arr); return NULL;}
				c_arr ++;
				command_arr = realloc(command_arr, sizeof(char*) * (c_arr + 1));
				if (!command_arr) { print_err(parse_realloc_er); free(command_arr); return NULL;}

			}

			s_buf[i - i_buf] = str[i];
			s_buf[i - i_buf + 1] = '\0';
			i_buf = i + 1;
			command_arr[c_arr] = s_buf;
			s_buf = calloc(strlen(str) + 1, sizeof(char));
			if (!s_buf) { print_err(parse_calloc_er); free(command_arr); return NULL;}
			c_arr ++;
			command_arr = realloc(command_arr, sizeof(char*) * (c_arr + 1));
			if (!command_arr) { print_err(parse_realloc_er); free(command_arr); return NULL;}

		} else {                                                                   // met an ordinary symbol

			if (flag) {

				flag = 0;
				i_buf = i;
				command_arr[c_arr] = s_buf;
				s_buf = calloc(strlen(str) + 1, sizeof(char));
				if (!s_buf) { print_err(parse_calloc_er); free(command_arr); return NULL;}
				c_arr ++;
				command_arr = realloc(command_arr, sizeof(char*) * (c_arr + 1));
				if (!s_buf) { print_err(parse_realloc_er); free(command_arr); return NULL;}

			}
			s_buf[i - i_buf] = str[i];

		}
	}

	if (s_buf)
		if (s_buf[0] != '\0') {

			command_arr[c_arr] = s_buf;
			c_arr ++;
			command_arr = realloc(command_arr, sizeof(char*) * (c_arr + 1));
			if (!s_buf) { print_err(parse_realloc_er); free(command_arr); return NULL; }

		} else free(s_buf);

	if (dq_flag) { print_err(parse_quotes_er); free_all(command_arr); return NULL;	}

	command_arr[c_arr] = NULL;

	return command_arr;
}


char ** parse_bracket(char * str) {
  char * s_buf = calloc(strlen(str) + 1, sizeof(char));
  char ** new_arr, ** bracket_arr = malloc(sizeof(char *) * 1);
  if (!bracket_arr) { print_err(parse_malloc_er); return NULL; }
  int c_arr = 0, i_buf = 0, bracket_count = 0, bracket_flag = 0;

  if (!s_buf) { print_err(parse_calloc_er); free(bracket_arr); return NULL; }

  for (int i = 0; i < strlen(str); ++i) {

    if (str[i] == '(') {                               // met '('

      if ((!bracket_flag) && s_buf[0]) {
        i_buf = i;
        bracket_arr[c_arr] = s_buf;
        s_buf = calloc(strlen(str) + 1, sizeof(char));
        if (!s_buf) { print_err(parse_calloc_er); free(bracket_arr); return NULL;}
        c_arr ++;
        bracket_arr = realloc(bracket_arr, sizeof(char*) * (c_arr + 1));
        if (!bracket_arr) { print_err(parse_realloc_er); free(bracket_arr); return NULL;}
      }

      bracket_count ++;
      bracket_flag = 1;

      s_buf[i - i_buf] = str[i];

    } else if (str[i] == ')') {          // met ')'

      bracket_count --;

      if (!bracket_flag) {
        print_err(parse_bracket_bracket_er);
        free(s_buf);
        free_all(bracket_arr);
        return NULL;
      }

      s_buf[i - i_buf] = str[i];

      if (!bracket_count) {
        bracket_flag = 0;
        i_buf = i + 1;
        bracket_arr[c_arr] = s_buf;
        s_buf = calloc(strlen(str) + 1, sizeof(char));
        if (!s_buf) { print_err(parse_calloc_er); free(bracket_arr); return NULL;}
        c_arr ++;
        bracket_arr = realloc(bracket_arr, sizeof(char*) * (c_arr + 1));
        if (!bracket_arr) { print_err(parse_realloc_er); free(bracket_arr); return NULL;}
      }

    } else {

      s_buf[i - i_buf] = str[i];

    }
  }

  if (s_buf)
    if (s_buf[0]) {

      bracket_arr[c_arr] = s_buf;
      c_arr ++;
      bracket_arr = realloc(bracket_arr, sizeof(char*) * (c_arr + 1));
      if (!s_buf) {
        print_err(parse_realloc_er);
        free(bracket_arr);
        return NULL;
      }
    } else free(s_buf);

  if (bracket_count) {
    print_err(parse_bracket_bracket_er);
    free_all(bracket_arr);
    return NULL;
  }

  bracket_arr[c_arr] = NULL;

  int arr_count = 0, newlen = 0;;
  char ** command_arr;

  for (int i = 0; bracket_arr[i]; i ++){
    if (bracket_arr[i][0] != '(') {
      new_arr = parse(bracket_arr[i]);
      newlen = len_arr(new_arr);

      if (!arr_count) command_arr = malloc(sizeof(char *) * (arr_count + newlen + 1));
      else command_arr = realloc(command_arr, sizeof(char *) * (arr_count + newlen + 1));

      memcpy(command_arr + arr_count, new_arr, (newlen + 1) * sizeof(char *));
      arr_count += newlen;

    } else {

      if (!arr_count) command_arr = malloc(sizeof(char *) * (arr_count + 2));
      else command_arr = realloc(command_arr, sizeof(char *) * (arr_count + 2));

      command_arr[arr_count] = bracket_arr[i];
      arr_count ++;
      command_arr[arr_count] = NULL;
    }
  }


  return command_arr;
}


int exec_cmd(char ** arr) {
  switch (fork()){
    case 0:
      execvp(arr[0], arr);
      print_err(exec_cmd_exec_er);
      exit(EXIT_FAILURE);
    case -1:
      print_err(exec_cmd_fork_er);
      return 1;
    default:
      return 0;
  }
}


int exec_pipe(char ** pipe_arr, int fon_flag) {
	char ** cmd_arr = calloc(sizeof(char *), len_arr(pipe_arr) + 1);

	int j_buf = 0, cmd = 0, first_flag = 1, status, return_status = 0;
	int fd[2], stand_output = dup(1);

	for (int i = 0; pipe_arr[i]; i ++) {

		if (strcmp(pipe_arr[i], "|")) {

			cmd_arr[j_buf] = pipe_arr[i];
			j_buf++;

		} else {

			pipe(fd);

			switch (fork()){
		    case 0:
					dup2(fd[1], 1);
					close(fd[0]);
					close(fd[1]);
		      execvp(cmd_arr[0], cmd_arr);
		      print_err(exec_pipe_exec_er);
		      exit(EXIT_FAILURE);
		    case -1:
		      print_err(exec_pipe_fork_er);
		      return_status = 1;
					goto fin;
		  }

      dup2(fd[0], 0);
			close(fd[0]);
			close(fd[1]);

			j_buf = 0;
      free(cmd_arr);
			cmd_arr = calloc(sizeof(char *), len_arr(pipe_arr));
		}
	}

	switch (fork()){
		case 0:
			execvp(cmd_arr[0], cmd_arr);
			print_err(exec_pipe_exec_er);
			exit(EXIT_FAILURE);
		case -1:
			print_err(exec_pipe_fork_er);
			return_status = 1;
	}

  fin:

  free(cmd_arr);

	close(fd[0]);
	close(fd[1]);

	if (fon_flag) {
		//printf("I killed myself\n");
		return return_status;
	}

	while(wait(&status) != -1);
  //printf("exec_pipe: pipes finished\n");
	return return_status || status;
}


int execute(char ** arr, int fon_flag, char * input, char * output, int output_flag){
  int status;
	int fp[2], redir_fp[2];

	switch (fork()){
		case 0:

			if (input) {
				redir_fp[0] = open(input, O_RDONLY);
				dup2(redir_fp[0], 0);
				close(redir_fp[0]);
			}

			if (output) {
				if (output_flag) redir_fp[1] = open(output, O_WRONLY | O_CREAT | O_APPEND, 0666);
				else redir_fp[1] = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0666);
				dup2(redir_fp[1], 1);
				close(redir_fp[1]);
			}

			if (fon_flag) {
				fp[0] = open("/dev/null", O_RDONLY);
				dup2(fp[0], 0);
				close(fp[0]);
				close(fp[1]);
			}

			if (exec_pipe(arr, fon_flag)) exit(EXIT_FAILURE);
      exit(EXIT_SUCCESS);

		case -1:

			print_err(execute_fork_er);
			return 1;

		default:

			wait(&status);

	}
	return status;
}


int exec_redir(char ** redir_arr, int fon_flag){
	char ** pipe_arr = calloc(sizeof(char*), len_arr(redir_arr) + 1);
	char ** redir_symbols = calloc(sizeof(char *), 4);
	redir_symbols[0] = "<";
	redir_symbols[1] = ">";
	redir_symbols[2] = ">>";

	int output_flag = 0, i = 0, return_status = 0;
	char * input = NULL, * output = NULL;

	while (redir_arr[i] && (isin(redir_arr[i], redir_symbols) == -1)) {
		pipe_arr[i] = redir_arr[i];
		i ++;
	}

	if (redir_arr[i] && (isin(redir_arr[i], redir_symbols) == 0)) {
		if (redir_arr[i + 1]) input = redir_arr[i + 1];
		else {
			print_err(exec_redir_filename_er);
			return_status = 1;
			goto fin;
		}
		i += 2;
	}

	if (redir_arr[i] && (isin(redir_arr[i], redir_symbols) >= 1)) {
		if (redir_arr[i + 1]) output = redir_arr[i + 1];
		else {
			print_err(exec_redir_filename_er);
			return_status = 1;
			goto fin;
		}
		if (isin(redir_arr[i], redir_symbols) == 2) output_flag = 1;
	}

	if (pipe_arr[0])
		return_status = return_status || execute(pipe_arr, fon_flag, input, output, output_flag);

	fin:
	free(pipe_arr);
	free(redir_symbols);
	return return_status;
}


int exec_bracket(char ** bracket_arr, int fon_flag){
  int len;
  char * new_command, ** buf_arr;


  if (bracket_arr && bracket_arr[0] && bracket_arr[0][0] == '(') {
    if (bracket_arr[1]) {
      print_err(exec_bracket_bracket_er);
      return 1;
    }

    new_command = bracket_arr[0] + 1;
    new_command[strlen(bracket_arr[0]) - 2] = '\0';
    buf_arr = calloc(sizeof(char *), 4);
    buf_arr[0] = MYSHELL;
    buf_arr[1] = "stdin";
    buf_arr[2] = new_command;
    return execute(buf_arr, fon_flag, NULL, NULL, 0);
  } else return exec_redir(bracket_arr, fon_flag);
}


int exec_cond(char ** cond_arr, int fon_flag) {
	char ** redir_arr = calloc(sizeof(char*), len_arr(cond_arr) + 1);
	int j_buf = 0, return_status = 0, sym_num = -1, i_arr;
	char ** condit_symbols = calloc(sizeof(char *), 3);
	condit_symbols[0] = "&&";
	condit_symbols[1] = "||";


	for (i_arr = 0; cond_arr[i_arr]; i_arr ++) {

		if ((sym_num = isin(cond_arr[i_arr], condit_symbols)) != -1) {

			return_status = exec_bracket(redir_arr, fon_flag);
			free(redir_arr);
			redir_arr = NULL;
			break;

		} else {

			redir_arr[j_buf] = cond_arr[i_arr];
			j_buf ++;

		}
	}


	if (redir_arr && redir_arr[0] && redir_arr[0][0])
		return_status = exec_bracket(redir_arr, fon_flag);

	if (cond_arr[i_arr] && cond_arr[i_arr + 1])
    if (sym_num == 1)
      return_status = return_status && exec_cond(cond_arr + i_arr + 1, fon_flag);
    else
      return_status = return_status || exec_cond(cond_arr + i_arr + 1, fon_flag);



	if (redir_arr) free(redir_arr);
	free(condit_symbols);
	return return_status;
}


int exec_fon(char ** command_arr) {
	char ** redir_arr = calloc(sizeof(char *), len_arr(command_arr) + 1);
	int j_buf = 0, return_status = 0, stat;

	for (int i = 0; command_arr[i]; i ++) {

		if (!strcmp(command_arr[i], "&")) {

			stat = exec_cond(redir_arr, 1);
			return_status = return_status || stat;

			j_buf = 0;
			free(redir_arr);
			redir_arr = calloc(sizeof(char *), len_arr(command_arr));

		} else if (!strcmp(command_arr[i], ";")) {

			stat = exec_cond(redir_arr, 0);
			return_status = return_status || stat;

			j_buf = 0;
			free(redir_arr);
			redir_arr = calloc(sizeof(char *), len_arr(command_arr));

		} else {

			redir_arr[j_buf] = command_arr[i];
			j_buf ++;

		}
	}

	if (redir_arr[0]) {
		stat = exec_cond(redir_arr, 0);
		return_status = return_status || stat;
	}
	free(redir_arr);
	return return_status;
}


int mycd (char ** arr){
	char * target = arr[1];
	if (!target) target = getenv("HOME");
	if (chdir(target)) {
		print_err(mycd_access_er);
		return 1;
	}
	return 0;
}


int main(int argc, char ** argv) {
	char ** command_arr, * str;
  int return_status = 0;
	FILE * fp, * buf_fp = NULL;

	if ((argc == 1) || (!strcmp(argv[1], "stdin")))
    fp = stdin;
	else if (argc >= 2) {
    buf_fp = fopen(argv[1], "r");
    fp = buf_fp;
	} else {
    print_err(main_inval_param_er);
    return 0;
  }

	if (!fp) { print_err(main_file_er); return 0; }

  if (argc == 3) {
    command_arr = parse_bracket(argv[2]);
    return_status = exec_fon(command_arr);
		free_all(command_arr);
    if (buf_fp) fclose(buf_fp);
  	return return_status;
  }

  print_sys("******************************************************");
  print_sys("*                WELCOME TO MY SHELL \\(o'ω'o)        *");
	print_sys("*                   (use with caution)               *");
  print_sys("******************************************************");
	print_sys("\nSmall guide (=^..^=)__:");
	print_sys("1. Input/output redirections organization");
	print_sys("     pipes < file > file");
	print_sys("   ( you can use >> instead of > )");
	print_sys("2. Background mode");
	print_sys("   standart output is used by default");
  print_sys("\nEnter your strings (ctrl + D to finish)");

	while (1) {
		printf("%s> %s", BLUE, WHITE);
		str = read_s(fp);
		if (!str) {
      return_status = 1;
      break;
    }

		command_arr = parse_bracket(str);

		if (!command_arr) continue;

		if (command_arr[0] && strcmp(command_arr[0], "cd") == 0) {
			return_status = mycd(command_arr);
			continue;
		} else return_status = exec_fon(command_arr);
		free(str);
		free_all(command_arr);
	}

	printf("%s", "\n");
  print_sys("See ya (' - ')/");

	if (buf_fp) fclose(buf_fp);
	return return_status;
}
