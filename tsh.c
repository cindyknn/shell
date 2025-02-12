/*
 * COMP 321 Project 1: Shell
 *
 * This program implements a tiny shell with job control.
 *
 * Cindy Nguyen (cn32)
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// You may assume that these constants are large enough.
#define MAXLINE 1024	  // max line size
#define MAXARGS 128	  // max args on a command line
#define MAXJOBS 16	  // max jobs at any point in time
#define MAXJID	(1 << 16) // max job ID

// The job states are:
#define UNDEF 0 // undefined
#define FG    1 // running in foreground
#define BG    2 // running in background
#define ST    3 // stopped

/*
 * The job state transitions and enabling actions are:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most one job can be in the FG state.
 */

struct Job {
	pid_t pid;	       // job PID
	int jid;	       // job ID [1, 2, ...]
	int state;	       // UNDEF, FG, BG, or ST
	char cmdline[MAXLINE]; // command line
};
typedef volatile struct Job *JobP;

/*
 * Define the jobs list using the "volatile" qualifier because it is accessed
 * by a signal handler (as well as the main program).
 */
static volatile struct Job jobs[MAXJOBS];
static int nextjid = 1; // next job ID to allocate

char **dirs;	// Variable to store the search paths parsed in initpath().
int dirs_count; // Variable to store the number of strings in dirs.

extern char **environ; // defined by libc

static char prompt[] = "tsh> "; // command line prompt (DO NOT CHANGE)
static bool verbose = false;	// If true, print additional output.

/*
 * The following array can be used to map a signal number to its name.
 * This mapping is valid for x86(-64)/Linux systems, such as CLEAR.
 * The mapping for other versions of Unix, such as FreeBSD, Mac OS X, or
 * Solaris, differ!
 */
static const char *const signame[NSIG] = {
	"Signal 0", /* Zero is not a valid signal. */
	"HUP",	    /* SIGHUP */
	"INT",	    /* SIGINT */
	"QUIT",	    /* SIGQUIT */
	"ILL",	    /* SIGILL */
	"TRAP",	    /* SIGTRAP */
	"ABRT",	    /* SIGABRT */
	"BUS",	    /* SIGBUS */
	"FPE",	    /* SIGFPE */
	"KILL",	    /* SIGKILL */
	"USR1",	    /* SIGUSR1 */
	"SEGV",	    /* SIGSEGV */
	"USR2",	    /* SIGUSR2 */
	"PIPE",	    /* SIGPIPE */
	"ALRM",	    /* SIGALRM */
	"TERM",	    /* SIGTERM */
	"STKFLT",   /* SIGSTKFLT */
	"CHLD",	    /* SIGCHLD */
	"CONT",	    /* SIGCONT */
	"STOP",	    /* SIGSTOP */
	"TSTP",	    /* SIGTSTP */
	"TTIN",	    /* SIGTTIN */
	"TTOU",	    /* SIGTTOU */
	"URG",	    /* SIGURG */
	"XCPU",	    /* SIGXCPU */
	"XFSZ",	    /* SIGXFSZ */
	"VTALRM",   /* SIGVTALRM */
	"PROF",	    /* SIGPROF */
	"WINCH",    /* SIGWINCH */
	"IO",	    /* SIGIO */
	"PWR",	    /* SIGPWR */
	"Signal 31"
};

// You must implement the following functions:

static bool builtin_cmd(char **argv);
static void do_bgfg(char **argv);
static void eval(const char *cmdline);
static void initpath(const char *pathstr);
static void waitfg(pid_t pid);

static void sigchld_handler(int signum);
static void sigint_handler(int signum);
static void sigtstp_handler(int signum);

// We are providing the following functions to you:

static bool parseline(const char *cmdline, char **argv);

static void sigquit_handler(int signum);

static bool addjob(JobP jobs, pid_t pid, int state, const char *cmdline);
static void clearjob(JobP job);
static bool deletejob(JobP jobs, pid_t pid);
static pid_t fgpid(JobP jobs);
static JobP getjobjid(JobP jobs, int jid);
static JobP getjobpid(JobP jobs, pid_t pid);
static void initjobs(JobP jobs);
static void listjobs(JobP jobs);
static int maxjid(JobP jobs);
static int pid2jid(pid_t pid);

static void app_error(const char *msg);
static void unix_error(const char *msg);
static void usage(void);

static void Sio_error(const char s[]);
static ssize_t Sio_putl(long v);
static ssize_t Sio_puts(const char s[]);
static void sio_error(const char s[]);
static void sio_ltoa(long v, char s[], int b);
static ssize_t sio_putl(long v);
static ssize_t sio_puts(const char s[]);
static void sio_reverse(char s[]);
static size_t sio_strlen(const char s[]);

/*
 * main - Performs the read-evaluate/execute loop.
 *
 * Requires:
 *   "argc" is an integer that indicates how many arguments were entered on the
 * command line when the program was started. "argv" is an array of pointers to
 * arrays of character objects.
 *
 * Effects:
 *   Executes the read-evaluate/execute loop program.
 */
int
main(int argc, char **argv)
{
	struct sigaction action;
	int c;
	char cmdline[MAXLINE];
	char *path = NULL;
	bool emit_prompt = true; // Emit a prompt by default.

	/*
	 * Redirect stderr to stdout (so that driver will get all output
	 * on the pipe connected to stdout).
	 */
	if (dup2(1, 2) < 0)
		unix_error("dup2 error");

	// Parse the command line.
	while ((c = getopt(argc, argv, "hvp")) != -1) {
		switch (c) {
		case 'h': // Print a help message.
			usage();
			break;
		case 'v': // Emit additional diagnostic info.
			verbose = true;
			break;
		case 'p': // Don't print a prompt.
			// This is handy for automatic testing.
			emit_prompt = false;
			break;
		default:
			usage();
		}
	}

	/*
	 * Install sigint_handler() as the handler for SIGINT (ctrl-c).  SET
	 * action.sa_mask TO REFLECT THE SYNCHRONIZATION REQUIRED BY YOUR
	 * IMPLEMENTATION OF sigint_handler().
	 */
	action.sa_handler = sigint_handler;
	action.sa_flags = SA_RESTART;
	if (sigemptyset(&action.sa_mask) < 0)
		unix_error("sigemptyset error");
	// Block SIGCHLD and SIGTSTP in sigint_handler.
	if (sigaddset(&action.sa_mask, SIGCHLD) < 0 ||
	    sigaddset(&action.sa_mask, SIGTSTP) < 0)
		unix_error("sigaddset error");
	if (sigaction(SIGINT, &action, NULL) < 0)
		unix_error("sigaction error");

	/*
	 * Install sigtstp_handler() as the handler for SIGTSTP (ctrl-z).  SET
	 * action.sa_mask TO REFLECT THE SYNCHRONIZATION REQUIRED BY YOUR
	 * IMPLEMENTATION OF sigtstp_handler().
	 */
	action.sa_handler = sigtstp_handler;
	action.sa_flags = SA_RESTART;
	if (sigemptyset(&action.sa_mask) < 0)
		unix_error("sigemptyset error");
	// Block SIGCHLD and SIGINT in sigtstp_handler.
	if (sigaddset(&action.sa_mask, SIGCHLD) < 0 ||
	    sigaddset(&action.sa_mask, SIGINT) < 0)
		unix_error("sigaddset error");
	if (sigaction(SIGTSTP, &action, NULL) < 0)
		unix_error("sigaction error");

	/*
	 * Install sigchld_handler() as the handler for SIGCHLD (terminated or
	 * stopped child).  SET action.sa_mask TO REFLECT THE SYNCHRONIZATION
	 * REQUIRED BY YOUR IMPLEMENTATION OF sigchld_handler().
	 */
	action.sa_handler = sigchld_handler;
	action.sa_flags = SA_RESTART;
	if (sigemptyset(&action.sa_mask) < 0)
		unix_error("sigemptyset error");
	// Block SIGINT and SIGTSTP in sigchld_handler.
	if (sigaddset(&action.sa_mask, SIGINT) < 0 ||
	    sigaddset(&action.sa_mask, SIGTSTP) < 0)
		unix_error("sigaddset error");
	if (sigaction(SIGCHLD, &action, NULL) < 0)
		unix_error("sigaction error");

	/*
	 * Install sigquit_handler() as the handler for SIGQUIT.  This handler
	 * provides a clean way for the test harness to terminate the shell.
	 * Preemption of the processor by the other signal handlers during
	 * sigquit_handler() does no harm, so action.sa_mask is set to empty.
	 */
	action.sa_handler = sigquit_handler;
	action.sa_flags = SA_RESTART;
	if (sigemptyset(&action.sa_mask) < 0)
		unix_error("sigemptyset error");
	if (sigaction(SIGQUIT, &action, NULL) < 0)
		unix_error("sigaction error");

	// Initialize the search path.
	path = getenv("PATH");
	initpath(path);

	// Initialize the jobs list.
	initjobs(jobs);

	// Execute the shell's read/eval loop.
	while (true) {

		// Read the command line.
		if (emit_prompt) {
			printf("%s", prompt);
			fflush(stdout);
		}
		if (fgets(cmdline, MAXLINE, stdin) == NULL && ferror(stdin))
			app_error("fgets error");
		if (feof(stdin)) // End of file (ctrl-d)
			exit(0);

		// Evaluate the command line.
		eval(cmdline);
		fflush(stdout);
	}

	// Control never reaches here.
	assert(false);
}

/*
 * eval - Evaluate the command line that the user has just typed in.
 *
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately.  Otherwise, fork a child process and
 * run the job in the context of the child.  If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.
 *
 * Requires:
 *   "cmdline" is a NUL ('\0') terminated string with a trailing
 *   '\n' character.  "cmdline" must contain less than MAXARGS
 *   arguments.
 *
 * Effects:
 *   Executes the command line evaluation program.
 */
static void
eval(const char *cmdline)
{
	pid_t pid;
	char *argv[MAXARGS];
	int bg = parseline(cmdline, argv);

	// If argv is not a built-in command.
	if (!builtin_cmd(argv)) {
		sigset_t mask, prev;
		sigemptyset(&mask);
		sigaddset(&mask, SIGCHLD);
		sigprocmask(SIG_BLOCK, &mask, &prev); // Block SIGCHLD.
		// Fork a child process.
		pid = fork();
		if (pid < 0) {
			unix_error("fork unsuccessful");
		}
		if (pid == 0) {
			// In the child process.

			// Reset handling of SIGINT and SIGTSTP to defaults.
			signal(SIGINT, SIG_DFL);
			signal(SIGTSTP, SIG_DFL);
			sigprocmask(SIG_SETMASK, &prev,
			    NULL); // Unblock SIGCHLD.
			setpgid(0, 0);

			char *final_path = "";
			if (strchr(argv[0], '/') != NULL ||
			    getenv("PATH") == NULL) {
				// argv[0] is a path name.
				final_path = strdup(argv[0]);
			} else {
				// argv[0] is an executable name.
				for (int i = 0; i < dirs_count; i++) {
					char *path = dirs[i];
					char *exec = malloc(strlen(path) +
					    strlen(argv[0]) +
					    1); // Remember to free this malloc
						// string.
					strcpy(exec, path);
					strcat(exec, argv[0]);
					if (access(exec, F_OK) == 0) {
						final_path = exec;
						break;
					} else {
						free(exec);
					}
				}
			}
			int exec_status = execve(final_path, argv, environ);
			free(final_path);

			if (exec_status < 0) {
				printf("%s: Command not found.\n", argv[0]);
				exit(1);
			}
		}

		setpgid(pid, pid);
		addjob(jobs, pid, bg ? BG : FG, cmdline);
		sigprocmask(SIG_SETMASK, &prev, NULL); // Unblock SIGCHLD.
		if (!bg) {
			waitfg(pid);
		} else {
			printf("[%d] (%d) %s", pid2jid(pid), pid, cmdline);
		}
	}

	return;
}

/*
 * parseline - Parse the command line and build the argv array.
 *
 * Requires:
 *   "cmdline" is a NUL ('\0') terminated string with a trailing
 *   '\n' character.  "cmdline" must contain less than MAXARGS
 *   arguments.
 *
 * Effects:
 *   Builds "argv" array from space delimited arguments on the command line.
 *   The final element of "argv" is set to NULL.  Characters enclosed in
 *   single quotes are treated as a single argument.  Returns true if
 *   the user has requested a BG job and false if the user has requested
 *   a FG job.
 *
 * Note:
 *   In the textbook, this function has the return type "int", but "bool"
 *   is more appropriate.
 */
static bool
parseline(const char *cmdline, char **argv)
{
	int argc;		    // number of args
	static char array[MAXLINE]; // local copy of command line
	char *buf = array;	    // ptr that traverses command line
	char *delim;		    // points to first space delimiter
	bool bg;		    // background job?

	strcpy(buf, cmdline);

	// Replace trailing '\n' with space.
	buf[strlen(buf) - 1] = ' ';

	// Ignore leading spaces.
	while (*buf != '\0' && *buf == ' ')
		buf++;

	// Build the argv list.
	argc = 0;
	if (*buf == '\'') {
		buf++;
		delim = strchr(buf, '\'');
	} else
		delim = strchr(buf, ' ');
	while (delim != NULL) {
		argv[argc++] = buf;
		*delim = '\0';
		buf = delim + 1;
		while (*buf != '\0' && *buf == ' ') // Ignore spaces.
			buf++;
		if (*buf == '\'') {
			buf++;
			delim = strchr(buf, '\'');
		} else
			delim = strchr(buf, ' ');
	}
	argv[argc] = NULL;

	// Ignore blank line.
	if (argc == 0)
		return (true);

	// Should the job run in the background?
	if ((bg = (*argv[argc - 1] == '&')) != 0)
		argv[--argc] = NULL;

	return (bg);
}

/*
 * builtin_cmd - If the user has typed a built-in command then execute
 *  it immediately.
 *
 * Requires:
 *   "argv" is an array of pointers to arrays of character objects. The first
 * element in the array is the command to be checked.
 *
 * Effects:
 *   Return true if the first element in the array is a built-in command, and
 * perform the necessary actions. Return false otherwise.
 *
 * Note:
 *   In the textbook, this function has the return type "int", but "bool"
 *   is more appropriate.
 */
static bool
builtin_cmd(char **argv)
{
	if (strcmp(argv[0], "quit") == 0) {
		exit(0);
	} else if (strcmp(argv[0], "bg") == 0 || strcmp(argv[0], "fg") == 0) {
		do_bgfg(argv);
		return true;
	} else if (strcmp(argv[0], "jobs") == 0) {
		listjobs(jobs);
		return true;
	}
	return false;
}

/*
 * do_bgfg - Execute the built-in bg and fg commands.
 *
 * Requires:
 *   "argv" is an array of pointers to arrays of character objects.
 *
 * Effects:
 *   Implements the bg and fg built-in commands.
 */
static void
do_bgfg(char **argv)
{
	JobP job = NULL;
	char *cmd = argv[0];
	char *param = argv[1];

	// Print out error when param is null.
	if (param == NULL) {
		printf("%s command requires PID or %%jobid argument\n", cmd);
		return;
	}

	char *pidptr;
	pid_t pid = strtol(param, &pidptr, 10);
	bool pid_fail = isdigit(param[0]) && (*pidptr != '\0');

	char *jidptr;
	char *param_jid = &param[1];
	int jid = strtol(param_jid, &jidptr, 10);
	bool jid_fail = (param[0] == '%') && (*jidptr != '\0');

	// Print out error when param is invalid.
	if ((param[0] != '%' && !isdigit(param[0])) || pid_fail || jid_fail) {
		printf("%s: argument must be a PID or %%jobid\n", cmd);
		return;
	}

	// Print out error when process does not exist.
	if (isdigit(param[0]) && (*pidptr == '\0')) {
		job = getjobpid(jobs, pid);
		if (job == NULL) {
			printf("(%d): No such process\n", pid);
			return;
		}
	}

	// Print out error when job does not exist.
	if ((param[0] == '%') && (*jidptr == '\0')) {
		job = getjobjid(jobs, jid);
		if (job == NULL) {
			printf("%%%d: No such job\n", jid);
			return;
		}
	}

	// Execute the built-in bg command.
	if (strcmp(cmd, "bg") == 0) {
		kill(-(job->pid), SIGCONT);
		job->state = BG;
		printf("[%d] (%d) %s", job->jid, job->pid, job->cmdline);
	}

	// Execute the built-in fg command.
	if (strcmp(cmd, "fg") == 0) {
		kill(-(job->pid), SIGCONT);
		job->state = FG;
		waitfg(job->pid);
	}

	return;
}

/*
 * waitfg - Block until process pid is no longer the foreground process.
 *
 * Requires:
 *   "pid" is an integer that indicates the process pid of the job.
 *
 * Effects:
 *   Waits for a foreground job to complete.
 */
static void
waitfg(pid_t pid)
{
	JobP job = getjobpid(jobs, pid);

	if (!job) {
		return;
	}

	sigset_t mask, prev;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &prev); // Block SIGCHLD
	// Use sigsuspend() to test whether the specified process is still
	// running in the foreground.
	while (job->pid == pid && job->state == FG) {
		sigsuspend(&prev);
	}
	sigprocmask(SIG_SETMASK, &prev, NULL); // Unblock SIGCHLD

	return;
}

/*
 * initpath - Perform all necessary initialization of the search path,
 *  which may be simply saving the path.
 *
 * Requires:
 *   "pathstr" is a valid search path.
 *
 * Effects:
 *   Parse the search path by colons into an array of directories, adding a
 * slash to the end of each string.
 */
static void
initpath(const char *pathstr)
{
	// Count number of directories by counting number of colons in the
	// search path + 1.
	int count = 1; //+1 for first directory without a colon
	for (int i = 0; i < (int)strlen(pathstr); i++) {
		if (pathstr[i] == ':') {
			count++;
		}
	}

	dirs_count = count;
	dirs = (char **)malloc(count * sizeof(char *));
	if (dirs == NULL) {
		unix_error("unsuccessful malloc for dirs");
	}
	int size = 0;

	char *path_copy = strdup(pathstr);
	if (path_copy == NULL) {
		unix_error("unsuccessful malloc for path_copy");
	}

	while (path_copy) {
		char *new_ptr = strsep(&path_copy, ":");
		if (strcmp(new_ptr, "") == 0) {
			// If the string is empty, take the current directory.
			char *pwd = getenv("PWD");
			char *exec = malloc(strlen(pwd) + 2);
			if (exec == NULL) {
				unix_error("unsuccessful malloc for exec");
			}
			strcpy(exec, pwd);
			strcat(exec, "/");
			dirs[size] = exec;
		} else {
			char *exec = malloc(strlen(new_ptr) + 2);
			if (exec == NULL) {
				unix_error("unsuccessful malloc for exec");
			}
			strcpy(exec, new_ptr);
			strcat(exec, "/");
			dirs[size] = exec;
		}
		size++;
	}

	return;
}

/*
 * The signal handlers follow.
 */

/*
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *  a child job terminates (becomes a zombie), or stops because it
 *  received a SIGSTOP or SIGTSTP signal.  The handler reaps all
 *  available zombie children, but doesn't wait for any other
 *  currently running children to terminate.
 *
 * Requires:
 *   "signum" is an integer that indicates the signal number, which in this case
 * should equal SIGCHLD.
 *
 * Effects:
 *   Catches SIGCHILD signals.
 */
static void
sigchld_handler(int signum)
{
	if (signum == SIGCHLD) { // Check if signum is SIGCHLD.
		pid_t pid;
		int status;
		int more_chld = 1;

		while (more_chld) {
			pid = waitpid(-1, &status, WUNTRACED | WNOHANG);
			more_chld = pid > 0;

			// Handle stopped jobs.
			if (WIFSTOPPED(status)) {
				JobP job = getjobpid(jobs, pid);
				if (job) {
					job->state = ST;
					Sio_puts("Job [");
					Sio_putl(pid2jid(pid));
					Sio_puts("] (");
					Sio_putl(pid);
					Sio_puts(") stopped by signal SIG");
					Sio_puts(signame[WSTOPSIG(status)]);
					Sio_puts("\n");
				}
			}
			// Handle exited jobs.
			else if (WIFEXITED(status)) {
				deletejob(jobs, pid);
			}
			// Handle terminated jobs.
			else if (WIFSIGNALED(status)) {
				int jid = pid2jid(pid);
				int success = deletejob(jobs, pid);
				if (success) {
					Sio_puts("Job [");
					Sio_putl(jid);
					Sio_puts("] (");
					Sio_putl(pid);
					Sio_puts(") terminated by signal SIG");
					Sio_puts(signame[WTERMSIG(status)]);
					Sio_puts("\n");
				}
			}
		}
	}

	return;
}

/*
 * sigint_handler - The kernel sends a SIGINT to the shell whenever the
 *  user types ctrl-c at the keyboard.  Catch it and send it along
 *  to the foreground job.
 *
 * Requires:
 *   "signum" is an integer that indicates the signal number, which in this case
 * should equal SIGINT.
 *
 * Effects:
 *    Catches SIGINT (ctrl-c) signals and interrupt the job.
 */
static void
sigint_handler(int signum)
{
	if (signum == SIGINT) { // Check if signum is SIGINT.
		pid_t pid = fgpid(jobs);
		if (pid > 0) {
			kill(-pid, SIGINT); // Interrupt the job.
		}
	}

	return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *  the user types ctrl-z at the keyboard.  Catch it and suspend the
 *  foreground job by sending it a SIGTSTP.
 *
 * Requires:
 *   "signum" is an integer that indicates the signal number, which in this case
 * should equal SIGTSTP.
 *
 * Effects:
 *   Catches SIGTSTP (ctrl-z) signals and stops the job.
 */
static void
sigtstp_handler(int signum)
{

	if (signum == SIGTSTP) { // Check if signum is SIGINT.
		pid_t pid = fgpid(jobs);
		if (pid > 0) {
			kill(-pid, SIGTSTP); // Stop the job.
		}
	}
	return;
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *  child shell by sending it a SIGQUIT signal.
 *
 * Requires:
 *   "signum" is SIGQUIT.
 *
 * Effects:
 *   Terminates the program.
 */
static void
sigquit_handler(int signum)
{

	// Prevent an "unused parameter" warning.
	(void)signum;
	Sio_puts("Terminating after receipt of SIGQUIT signal\n");
	_exit(1);
}

/*
 * This comment marks the end of the signal handlers.
 */

/*
 * The following helper routines manipulate the jobs list.
 */

/*
 * Requires:
 *   "job" points to a job structure.
 *
 * Effects:
 *   Clears the fields in the referenced job structure.
 */
static void
clearjob(JobP job)
{

	job->pid = 0;
	job->jid = 0;
	job->state = UNDEF;
	job->cmdline[0] = '\0';
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Initializes the jobs list to an empty state.
 */
static void
initjobs(JobP jobs)
{
	int i;

	for (i = 0; i < MAXJOBS; i++)
		clearjob(&jobs[i]);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Returns the largest allocated job ID.
 */
static int
maxjid(JobP jobs)
{
	int i, max = 0;

	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].jid > max)
			max = jobs[i].jid;
	return (max);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures, and "cmdline" is
 *   a properly terminated string.
 *
 * Effects:
 *   Tries to add a job to the jobs list.  Returns true if the job was added
 *   and false otherwise.
 */
static bool
addjob(JobP jobs, pid_t pid, int state, const char *cmdline)
{
	int i;

	if (pid < 1)
		return (false);
	for (i = 0; i < MAXJOBS; i++) {
		if (jobs[i].pid == 0) {
			jobs[i].pid = pid;
			jobs[i].state = state;
			jobs[i].jid = nextjid++;
			if (nextjid > MAXJOBS)
				nextjid = 1;
			// Remove the "volatile" qualifier using a cast.
			strcpy((char *)jobs[i].cmdline, cmdline);
			if (verbose) {
				printf("Added job [%d] %d %s\n", jobs[i].jid,
				    (int)jobs[i].pid, jobs[i].cmdline);
			}
			return (true);
		}
	}
	printf("Tried to create too many jobs\n");
	return (false);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Tries to delete the job from the jobs list whose PID equals "pid".
 *   Returns true if the job was deleted and false otherwise.
 */
static bool
deletejob(JobP jobs, pid_t pid)
{
	int i;

	if (pid < 1)
		return (false);
	for (i = 0; i < MAXJOBS; i++) {
		if (jobs[i].pid == pid) {
			clearjob(&jobs[i]);
			nextjid = maxjid(jobs) + 1;
			return (true);
		}
	}
	return (false);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Returns the PID of the current foreground job or 0 if no foreground
 *   job exists.
 */
static pid_t
fgpid(JobP jobs)
{
	int i;

	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].state == FG)
			return (jobs[i].pid);
	return (0);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Returns a pointer to the job structure with process ID "pid" or NULL if
 *   no such job exists.
 */
static JobP
getjobpid(JobP jobs, pid_t pid)
{
	int i;

	if (pid < 1)
		return (NULL);
	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].pid == pid)
			return (&jobs[i]);
	return (NULL);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Returns a pointer to the job structure with job ID "jid" or NULL if no
 *   such job exists.
 */
static JobP
getjobjid(JobP jobs, int jid)
{
	int i;

	if (jid < 1)
		return (NULL);
	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].jid == jid)
			return (&jobs[i]);
	return (NULL);
}

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Returns the job ID for the job with process ID "pid" or 0 if no such
 *   job exists.
 */
static int
pid2jid(pid_t pid)
{
	int i;

	if (pid < 1)
		return (0);
	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].pid == pid)
			return (jobs[i].jid);
	return (0);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Prints the jobs list.
 */
static void
listjobs(JobP jobs)
{
	int i;

	for (i = 0; i < MAXJOBS; i++) {
		if (jobs[i].pid != 0) {
			printf("[%d] (%d) ", jobs[i].jid, (int)jobs[i].pid);
			switch (jobs[i].state) {
			case BG:
				printf("Running ");
				break;
			case FG:
				printf("Foreground ");
				break;
			case ST:
				printf("Stopped ");
				break;
			default:
				printf("listjobs: Internal error: "
				       "job[%d].state=%d ",
				    i, jobs[i].state);
			}
			printf("%s", jobs[i].cmdline);
		}
	}
}

/*
 * This comment marks the end of the jobs list helper routines.
 */

/*
 * Other helper routines follow.
 */

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Prints a help message.
 */
static void
usage(void)
{

	printf("Usage: shell [-hvp]\n");
	printf("   -h   print this message\n");
	printf("   -v   print additional diagnostic information\n");
	printf("   -p   do not emit a command prompt\n");
	exit(1);
}

/*
 * Requires:
 *   "msg" is a properly terminated string.
 *
 * Effects:
 *   Prints a Unix-style error message and terminates the program.
 */
static void
unix_error(const char *msg)
{

	fprintf(stdout, "%s: %s\n", msg, strerror(errno));
	exit(1);
}

/*
 * Requires:
 *   "msg" is a properly terminated string.
 *
 * Effects:
 *   Prints "msg" and terminates the program.
 */
static void
app_error(const char *msg)
{

	fprintf(stdout, "%s\n", msg);
	exit(1);
}

/*
 * Requires:
 *   The character array "s" is sufficiently large to store the ASCII
 *   representation of the long "v" in base "b".
 *
 * Effects:
 *   Converts a long "v" to a base "b" string, storing that string in the
 *   character array "s" (from K&R).  This function can be safely called by
 *   a signal handler.
 */
static void
sio_ltoa(long v, char s[], int b)
{
	int c, i = 0;

	do
		s[i++] = (c = v % b) < 10 ? c + '0' : c - 10 + 'a';
	while ((v /= b) > 0);
	s[i] = '\0';
	sio_reverse(s);
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Reverses a string (from K&R).  This function can be safely called by a
 *   signal handler.
 */
static void
sio_reverse(char s[])
{
	int c, i, j;

	for (i = 0, j = sio_strlen(s) - 1; i < j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Computes and returns the length of the string "s".  This function can be
 *   safely called by a signal handler.
 */
static size_t
sio_strlen(const char s[])
{
	size_t i = 0;

	while (s[i] != '\0')
		i++;
	return (i);
}

/*
 * Requires:
 *   None.
 *
 * Effects:
 *   Prints the long "v" to stdout using only functions that can be safely
 *   called by a signal handler, and returns either the number of characters
 *   printed or -1 if the long could not be printed.
 */
static ssize_t
sio_putl(long v)
{
	char s[128];

	sio_ltoa(v, s, 10);
	return (sio_puts(s));
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Prints the string "s" to stdout using only functions that can be safely
 *   called by a signal handler, and returns either the number of characters
 *   printed or -1 if the string could not be printed.
 */
static ssize_t
sio_puts(const char s[])
{

	return (write(STDOUT_FILENO, s, sio_strlen(s)));
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Prints the string "s" to stdout using only functions that can be safely
 *   called by a signal handler, and exits the program.
 */
static void
sio_error(const char s[])
{

	sio_puts(s);
	_exit(1);
}

/*
 * Requires:
 *   None.
 *
 * Effects:
 *   Prints the long "v" to stdout using only functions that can be safely
 *   called by a signal handler.  Either returns the number of characters
 *   printed or exits if the long could not be printed.
 */
static ssize_t
Sio_putl(long v)
{
	ssize_t n;

	if ((n = sio_putl(v)) < 0)
		sio_error("Sio_putl error");
	return (n);
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Prints the string "s" to stdout using only functions that can be safely
 *   called by a signal handler.  Either returns the number of characters
 *   printed or exits if the string could not be printed.
 */
static ssize_t
Sio_puts(const char s[])
{
	ssize_t n;

	if ((n = sio_puts(s)) < 0)
		sio_error("Sio_puts error");
	return (n);
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Prints the string "s" to stdout using only functions that can be safely
 *   called by a signal handler, and exits the program.
 */
static void
Sio_error(const char s[])
{

	sio_error(s);
}

// Prevent "unused function" and "unused variable" warnings.
static const void *dummy_ref[] = { Sio_error, Sio_putl, addjob, builtin_cmd,
	deletejob, do_bgfg, dummy_ref, fgpid, getjobjid, getjobpid, listjobs,
	parseline, pid2jid, signame, waitfg };
