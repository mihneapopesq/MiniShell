// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ 0
#define WRITE 1

#define CHECK_COMMAND_SANITY(c, level) \
	do {                               \
		if ((c) == NULL || (level) < 0)\
			return SHELL_EXIT;         \
	} while (0)


#define CHECK_SIMPLE_SANITY(s)                    \
	do {                                          \
		if ((s) == NULL)                          \
			return shell_exit();                  \
	} while (0)


/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	if (!dir || dir->next_word != NULL) {
		if (dir == NULL) {
			const char *home_dir = getenv("HOME");

			if (home_dir == NULL)
				return false;
			return chdir(home_dir) == 0;
		}
		return false;
	}

	char *new_path = get_word(dir);

	if (new_path == NULL)
		return false;

	int result = chdir(new_path);

	free(new_path);
	return result == 0;
}


/**
 * Internal exit/quit command.	if (s == NULL)
		return shell_exit();
*/
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	return SHELL_EXIT; /* TODO: Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */

void handle_redirection(word_t *redirection, int flags, mode_t mode)
{
	if (redirection) {
		char *filename = get_word(redirection); // Assumes get_word extracts the file name from word_t
		int fd = open(filename, flags, mode);

		if (fd == -1)
			perror("Failed to open file for redirection");
		else
			close(fd); // Close the file descriptor as it's no longer needed
		free(filename); // Free the allocated filename after use
	}
}


static int environment_assign(simple_command_t *s)
{
	if (!s || !s->verb || !s->verb->next_part || !s->verb->next_part->next_part) {
		fprintf(stderr, "Invalid command format for setting environment variable.\n");
		return -1;
	}

	const char *name = s->verb->string;
	char *value = get_word(s->verb->next_part->next_part);

	if (value == NULL) {
		fprintf(stderr, "Failed to retrieve environment variable value.\n");
		return -1;
	}

	int result = setenv(name, value, 1);

	free(value);

	return result;
}

static void setup_redirection(const char *path, int new_fd, int flags)
{
	int fd = open(path, flags, 0644);

	if (fd < 0) {
		perror("Failed to open redirection file");
		exit(EXIT_FAILURE);
	}
	if (dup2(fd, new_fd) < 0) {
		perror("Failed to set up redirection");
		close(fd);
		exit(EXIT_FAILURE);
	}
	close(fd);
}

static void redirect_if_required(simple_command_t *s)
{
	// Check if input redirection is specified
	if (s->in) {
		// Set up redirection for standard input using the specified file
		setup_redirection(get_word(s->in), STDIN_FILENO, O_RDONLY);
	}
	// Check if output and error are redirected to the same file
	if (s->out && s->err && strcmp(get_word(s->out), get_word(s->err)) == 0) {
		// Set up redirection for both stdout and stderr to the same file
		setup_redirection(get_word(s->out), STDOUT_FILENO,
						s->io_flags & IO_OUT_APPEND ? O_WRONLY | O_APPEND | O_CREAT : O_WRONLY | O_TRUNC | O_CREAT);
		// Duplicate stdout to stderr
		dup2(STDOUT_FILENO, STDERR_FILENO);
	} else {
		// Set up redirection for stdout if specified
		if (s->out) {
			setup_redirection(get_word(s->out), STDOUT_FILENO,
							s->io_flags & IO_OUT_APPEND ?
							O_WRONLY | O_APPEND | O_CREAT : O_WRONLY | O_TRUNC | O_CREAT);
		}
		// Set up redirection for stderr if specified
		if (s->err) {
			setup_redirection(get_word(s->err), STDERR_FILENO,
							s->io_flags & IO_ERR_APPEND ?
							O_WRONLY | O_APPEND | O_CREAT : O_WRONLY | O_TRUNC | O_CREAT);
		}
	}
}



static int execute_child_process(simple_command_t *s, char *verb)
{
	redirect_if_required(s);

	char **argv;
	int size;

	argv = get_argv(s, &size);
	if (execvp(verb, argv) < 0) {
		fprintf(stderr, "Execution failed for '%s'\n", verb);
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0; i < size; ++i)
		free(argv[i]);

	free(argv);
	exit(EXIT_SUCCESS);
}

static int handle_external_command(simple_command_t *s, char *verb)
{
	// Start a new process to handle the command
	pid_t child_pid = fork();

	// Check for fork failure
	if (child_pid < 0) {
		perror("Fork failed");
		free(verb);  // Ensure resources are cleaned up properly
		return -1;   // Return error code on fork failure
	} else if (child_pid > 0) {
		int status;
		// Wait for the child process to finish
		if (waitpid(child_pid, &status, 0) == -1) {
			perror("Error waiting for child process");
			free(verb);  // Clean up verb resource
			return SHELL_EXIT;  // Return shell exit code on wait failure
		}
		free(verb);  // Clean up verb after waiting
		// Check if the child exited normally and return its status
		return WIFEXITED(status) ? WEXITSTATUS(status) : SHELL_EXIT;
	}
	// Child process executes the command
	return execute_child_process(s, verb);
}



static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	CHECK_SIMPLE_SANITY(s);
	/* TODO: If builtin command, execute the command. */

	char *verb = get_word(s->verb);

	if (strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0) {
		free(verb);
		return shell_exit();
	}
	if (strcmp(verb, "cd") == 0) {
		free(verb);
		handle_redirection(s->out, O_WRONLY | O_TRUNC | O_CREAT, 0644);
		handle_redirection(s->err, O_WRONLY | O_TRUNC | O_CREAT, 0644);

		bool res = shell_cd(s->params);

		return res ? 0 : -1;
	}

	/* TODO: If variable assignment, execute the assignment and return
	 *  the exit status.
	 */

	if (verb && strchr(verb, '=')) {
		free(verb);
		return environment_assign(s);
	}

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	return handle_external_command(s, verb);
	/* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static int run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	pid_t pid1, pid2;
	int status1, status2;

	// Fork the first child to execute the first command
	pid1 = fork();
	switch (pid1) {
	case -1:
		perror("Failed to fork for cmd1");
		return -1;  // Return error if the fork fails
	case 0:
		// In the child process, execute the first command and exit with its status
		exit(parse_command(cmd1, level + 1, father));
	}

	// Fork the second child to execute the second command
	pid2 = fork();
	switch (pid2) {
	case -1:
		perror("Failed to fork for cmd2");
		return -1;  // Return error if the fork fails
	case 0:
		// In the child process, execute the second command and exit with its status
		exit(parse_command(cmd2, level + 1, father));
	}

	// Wait for the first child and check for errors
	if (waitpid(pid1, &status1, 0) == -1) {
		perror("Error waiting for cmd1");
		return -1;  // Return error if waiting fails
	}
	// Wait for the second child and check for errors
	if (waitpid(pid2, &status2, 0) == -1) {
		perror("Error waiting for cmd2");
		return -1;  // Return error if waiting fails
	}

	// Check if both commands exited normally and print their exit statuses
	if (WIFEXITED(status1) && WIFEXITED(status2)) {
		int exit_status1 = WEXITSTATUS(status1);
		int exit_status2 = WEXITSTATUS(status2);

		printf("Command 1 exited with status %d, Command 2 exited with status %d\n",
		exit_status1, exit_status2);
		return 0;  // Return success if both commands exit normally
	}

	return -1;  // Return error if any command didn't exit normally
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static int run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	int pipefd[2];
	// Attempt to create a pipe and exit if unsuccessful
	if (pipe(pipefd) != 0) {
		perror("Failed to create pipe");
		exit(EXIT_FAILURE);
	}

	// Fork the first process to execute the first command
	pid_t pid1 = fork();

	switch (pid1) {
	case -1:
		perror("Failed to fork for first command");
		// Clean up pipe resources if fork fails
		close(pipefd[0]);
		close(pipefd[1]);
		exit(EXIT_FAILURE);

	case 0:
		// Close the unused read end of the pipe in the child process
		close(pipefd[READ]);
		// Redirect stdout of the first command to the pipe
		if (dup2(pipefd[WRITE], STDOUT_FILENO) < 0) {
			perror("Failed to redirect stdout for first command");
			close(pipefd[WRITE]);
			exit(EXIT_FAILURE);
		}
		close(pipefd[WRITE]); // Close the write end after duplication
		// Execute the first command and exit with its status
		exit(parse_command(cmd1, level, father));
	}

	// Fork the second process to execute the second command
	pid_t pid2 = fork();

	switch (pid2) {
	case -1:
		perror("Failed to fork for second command");
		// Ensure resources are freed if second fork fails
		close(pipefd[0]);
		close(pipefd[1]);
		// Make sure to clean up the first child if the second fork fails
		waitpid(pid1, NULL, 0);
		exit(EXIT_FAILURE);

	case 0:
		// Close the unused write end of the pipe in the second child
		close(pipefd[WRITE]);
		// Redirect stdin of the second command from the pipe
		if (dup2(pipefd[READ], STDIN_FILENO) < 0) {
			perror("Failed to redirect stdin for second command");
			close(pipefd[READ]);
			exit(EXIT_FAILURE);
		}
		close(pipefd[READ]); // Close the read end after duplication
		// Execute the second command and exit with its status
		exit(parse_command(cmd2, level, father));
	}

	// Parent closes both ends of the pipe then waits for both children
	close(pipefd[READ]);
	close(pipefd[WRITE]);

	// Wait for both child processes to finish
	int status1, status2;

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	// Return the exit status of the second command if it exited normally
	if (WIFEXITED(status2))
		return WEXITSTATUS(status2);

	// If the second command didn't exit normally, return an error
	return -1;
}


/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* sanity checks */

	CHECK_COMMAND_SANITY(c, level);

	/* Execute a simple command. */
	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level + 1, c); /* Actual exit code of command. */

	int res = 0;

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
		res = parse_command(c->cmd2, level + 1, c);
		return res;

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		res = run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		res = parse_command(c->cmd1, level + 1, c);

		if (res)
			res = parse_command(c->cmd2, level + 1, c);

		return res;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */

		res = parse_command(c->cmd1, level + 1, c);

		if (!res)
			res = parse_command(c->cmd2, level + 1, c);

		return res;

	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		res = (int)run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		return res;

	default:
		return SHELL_EXIT;
	}

	return res; /* Actual exit code of command. */
}
