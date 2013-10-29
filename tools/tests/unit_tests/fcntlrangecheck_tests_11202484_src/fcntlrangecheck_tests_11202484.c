#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

#define SUCCESS 0
#define FAILURE -1

int do_fcntl_lock(int fd, int cmd, short lock_type, off_t start, short when, off_t len, int ret){
  struct flock fl;
  bzero(&fl, sizeof(fl));
  fl.l_start = start;
  fl.l_len = len;
  fl.l_type = lock_type;
  fl.l_whence = when;
  errno = 0;
  int retval = fcntl(fd, cmd, &fl);
  printf ("fcntl with flock(%lld,%lld,%d,%d) returned %d and errno %d \n", start, len, lock_type, when, retval, errno);
  if ( retval < 0)
    perror("fcntl");

  if (retval != ret) {
    printf("[FAILED] fcntl test failed\n");
    exit(-1);
  }
  return retval;
}

#define	read_lock(fd, offset, whence, len, ret) \
		do_fcntl_lock(fd, F_SETLK, F_RDLCK, offset, whence, len, ret)
#define	readw_lock(fd, offset, whence, len, ret) \
		do_fcntl_lock(fd, F_SETLKW, F_RDLCK, offset, whence, len, ret)
#define	write_lock(fd, offset, whence, len, ret) \
		do_fcntl_lock(fd, F_SETLK, F_WRLCK, offset, whence, len, ret)
#define	writew_lock(fd, offset, whence, len, ret) \
		do_fcntl_lock(fd, F_SETLKW, F_WRLCK, offset, whence, len, ret)
#define	un_lock(fd, offset, whence, len, ret) \
		do_fcntl_lock(fd, F_SETLK, F_UNLCK, offset, whence, len, ret)
#define	is_read_lock(fd, offset, whence, len, ret) \
		do_fcntl_lock(fd, F_GETLK, F_RDLCK, offset, whence, len, ret)
#define	is_write_lock(fd, offset, whence, len, ret) \
		do_fcntl_lock(fd, F_GETLK, F_WRLCK, offset, whence, len, ret)


int main(){
  int fd = 0;
  char *tmpfile ="/tmp/fcntltry.txt";

  unlink(tmpfile);
  fd = creat(tmpfile, S_IRWXU);
  if (fd < 0) {
        perror("creat");
        goto failed;
   }

  /* fcntl with seek position set to 1  */
  if (lseek(fd, (off_t)1, SEEK_SET) != 1){
        perror("lseek");
        goto failed;
  }
  off_t lock_start = 0, lock_len = 0;

  printf("Testing with SEEK_SET\n");

  /* testing F_GETLK for SEEK_SET with lock_start = constant and len changes */
  lock_start = 0;
  is_read_lock(fd, lock_start, SEEK_SET, 0, SUCCESS);
  is_read_lock(fd, lock_start, SEEK_SET, LLONG_MAX, SUCCESS);
  is_read_lock(fd, lock_start, SEEK_SET, LLONG_MIN, FAILURE);

  /* testing F_GETLK for SEEK_SET with len fixed 0 and lock_start changing */
  lock_len = 0;
  is_read_lock(fd, 0, SEEK_SET, lock_len, SUCCESS);
  is_read_lock(fd, LLONG_MAX, SEEK_SET, lock_len, SUCCESS);
  is_read_lock(fd, LLONG_MIN, SEEK_SET, lock_len, FAILURE);
  
  /* testing F_GETLK for SEEK_SET with len fixed max and lock_start changing */
  lock_len = LLONG_MAX;
  is_read_lock(fd, 0, SEEK_SET, lock_len, SUCCESS);
  is_read_lock(fd, 1, SEEK_SET, lock_len, SUCCESS);
  is_read_lock(fd, 2, SEEK_SET, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MAX, SEEK_SET, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MIN, SEEK_SET, lock_len, FAILURE);

  /* testing F_GETLK for SEEK_SET with len fixed min and lock_start changing */
  lock_len = LLONG_MIN;
  is_read_lock(fd, 0, SEEK_SET, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MAX, SEEK_SET, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MIN, SEEK_SET, lock_len, FAILURE);
  
  /* testing F_GETLK for SEEK_SET with len fixed min and lock_start changing */
  lock_len = 20;
  is_read_lock(fd, 0, SEEK_SET, lock_len, SUCCESS);
  is_read_lock(fd, 100, SEEK_SET, lock_len, SUCCESS);
  is_read_lock(fd, -100, SEEK_SET, lock_len, FAILURE);
  
  /* testing F_GETLK for SEEK_SET with len fixed min and lock_start changing */
  lock_len = -20;
  is_read_lock(fd, 0, SEEK_SET, lock_len, FAILURE);
  is_read_lock(fd, 100, SEEK_SET, lock_len, SUCCESS);
  is_read_lock(fd, -100, SEEK_SET, lock_len, FAILURE);

  printf("Testing with SEEK_CUR with offset 1 \n");

  /* testing F_GETLK for SEEK_CUR with lock_start = constant and len changes */
  lock_start = 0;
  is_read_lock(fd, lock_start, SEEK_CUR, 0, SUCCESS);
  is_read_lock(fd, lock_start, SEEK_CUR, LLONG_MAX, SUCCESS);
  is_read_lock(fd, lock_start, SEEK_CUR, LLONG_MIN, FAILURE);

  /* testing F_GETLK for SEEK_CUR with len fixed 0 and lock_start changing */
  lock_len = 0;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, SUCCESS);
  is_read_lock(fd, LLONG_MAX, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MAX - 1, SEEK_CUR, lock_len, SUCCESS);
  is_read_lock(fd, LLONG_MIN, SEEK_CUR, lock_len, FAILURE);
  
  /* testing F_GETLK for SEEK_CUR with len fixed max and lock_start changing */
  lock_len = LLONG_MAX;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, SUCCESS);
  is_read_lock(fd, 1, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, 2, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MAX, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MIN, SEEK_CUR, lock_len, FAILURE);

  /* testing F_GETLK for SEEK_CUR with len fixed min and lock_start changing */
  lock_len = LLONG_MIN;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MAX, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MIN, SEEK_CUR, lock_len, FAILURE);
  
  /* testing F_GETLK for SEEK_CUR with len fixed min and lock_start changing */
  lock_len = 20;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, SUCCESS);
  is_read_lock(fd, 100, SEEK_CUR, lock_len, SUCCESS);
  is_read_lock(fd, -100, SEEK_CUR, lock_len, FAILURE);
  
  /* testing F_GETLK for SEEK_CUR with len fixed min and lock_start changing */
  lock_len = -20;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, 100, SEEK_CUR, lock_len, SUCCESS);
  is_read_lock(fd, -100, SEEK_CUR, lock_len, FAILURE);

  close(fd);

  unlink(tmpfile);
  fd = creat(tmpfile, S_IRWXU);
  if (fd < 0) {
        perror("creat");
        goto failed;
   }

  /* fcntl with seek position set to 1  */
  if (lseek(fd, (off_t)LLONG_MAX - 1, SEEK_SET) != (LLONG_MAX - 1)){
        perror("lseek");
        goto failed;
  }


  printf("Testing with SEEK_CUR with offset LLONG_MAX - 1\n");

 /* testing F_GETLK for SEEK_CUR with lock_start = constant and len changes */
  lock_start = 0;
  is_read_lock(fd, lock_start, SEEK_CUR, 0, SUCCESS);
  is_read_lock(fd, lock_start, SEEK_CUR, LLONG_MAX, FAILURE);
  is_read_lock(fd, lock_start, SEEK_CUR, LLONG_MIN, FAILURE);
  is_read_lock(fd, lock_start, SEEK_CUR, LLONG_MIN + 2, SUCCESS);

  /* testing F_GETLK for SEEK_CUR with len fixed 0 and lock_start changing */
  lock_len = 0;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, SUCCESS);
  is_read_lock(fd, LLONG_MAX, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MIN, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MIN + 2, SEEK_CUR, lock_len, SUCCESS);
  
  /* testing F_GETLK for SEEK_CUR with len fixed max and lock_start changing */
  lock_len = LLONG_MAX;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MAX, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MIN, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MIN + 2, SEEK_CUR, lock_len, SUCCESS);

  /* testing F_GETLK for SEEK_CUR with len fixed min and lock_start changing */
  lock_len = LLONG_MIN;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MAX, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, LLONG_MIN, SEEK_CUR, lock_len, FAILURE);
  
  /* testing F_GETLK for SEEK_CUR with len fixed min and lock_start changing */
  lock_len = 20;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, -100, SEEK_CUR, lock_len, SUCCESS);
  
  /* testing F_GETLK for SEEK_CUR with len fixed min and lock_start changing */
  lock_len = -20;
  is_read_lock(fd, 0, SEEK_CUR, lock_len, SUCCESS);
  is_read_lock(fd, 100, SEEK_CUR, lock_len, FAILURE);
  is_read_lock(fd, -100, SEEK_CUR, lock_len, SUCCESS);


  printf("[PASSED] fcntl test passed \n");
  return 0;
failed:
  printf("[FAILED] fcntl test failed\n");
  return -1;

}
