#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

#include "liburing.h"

#define BUFSIZE 4096
#define NENTRIES 64

struct promo_echo_user_data {
  enum {
    RECV,
    SEND,
    TIMEOUT,
    CLOSE
  } state;
  int fd;
  size_t size;
  uint8_t data[BUFSIZE];
};

static int setup_accept(struct io_uring *uring, struct sockaddr_in *addr, socklen_t *paddrlen,
		 int s) {
  
  struct io_uring_sqe *sqe = io_uring_get_sqe(uring);
  if (!sqe) {
    return 6;
  }
  io_uring_prep_accept(sqe, s, (struct sockaddr *)addr, paddrlen, 0);
  io_uring_sqe_set_data64(sqe, 1);
  int ret = io_uring_submit(uring);
  if (ret != 1) {
    return 7;
  }
  //printf("setup accept done\n");
  return 0;
}

static int setup_recv(struct io_uring *uring, struct promo_echo_user_data *u, int flags) {
  
  u->state = RECV;
  struct io_uring_sqe *sqe = io_uring_get_sqe(uring);
  if (!sqe) {
    // ToDo: graceful degradation
    return 9;
  }
  io_uring_sqe_set_data(sqe, u);
  io_uring_prep_recv(sqe, u->fd, u->data, sizeof(u->data), flags);
  int ret = io_uring_submit(uring);
  if (ret != 1) {
    // ToDo: graceful degradation
    return 10;
  }
  return 0;
}

static int setup_send(struct io_uring *uring, struct promo_echo_user_data *u) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(uring);
  if (!sqe) {
    // ToDo: graceful degradation
    return 9;
  }
  u->state = SEND;
  io_uring_sqe_set_data(sqe, u);
  io_uring_prep_send(sqe, u->fd, u->data, u->size, 0);
  int ret = io_uring_submit(uring);
  if (ret != 1) {
    // ToDo: graceful degradation
    return 10;
  }
  return 0;
}

static int setup_to(struct io_uring *uring, struct promo_echo_user_data *u) {
  struct __kernel_timespec ts = {
    .tv_sec = 5,
	    .tv_nsec = 0
  };
  struct io_uring_sqe *sqe = io_uring_get_sqe(uring);
  if (!sqe) {
    // ToDo: graceful degradation
    return 9;
  }
  u->state = TIMEOUT;
  io_uring_sqe_set_data(sqe, u);
  io_uring_prep_timeout(sqe, &ts, 0, IORING_TIMEOUT_ETIME_SUCCESS);
  int ret = io_uring_submit(uring);
  if (ret != 1) {
    // ToDo: graceful degradation
    return 10;
  }
  return 0;
}

static int setup_close(struct io_uring *uring, struct promo_echo_user_data *u) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(uring);
  if (!sqe) {
    // ToDo: graceful degradation
    return 9;
  }
  u->state = CLOSE;
  io_uring_sqe_set_data(sqe, u);
  io_uring_prep_close(sqe, u->fd);
  int ret = io_uring_submit(uring);
  if (ret != 1) {
    // ToDo: graceful degradation
    return 10;
  }
  return 0;
}


static int s;
static struct io_uring ring;
static volatile bool do_terminate = false;

static void cleanup(void) {
  close(s);
  io_uring_queue_exit(&ring);
}

static void sigint(int) {
  do_terminate = true;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    return 1;
  }
  uint16_t port = atoi(argv[1]);

  struct io_uring_sqe *sqe;

  struct sockaddr_in addr = {};
  socklen_t addrlen = sizeof(addr);
  int ret;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s = socket(PF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    return 2;
  }
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(s);
    return 3;
  }
  if (listen(s, 50) < 0) {
    close(s);
    return 4;
  }

  if (io_uring_queue_init(NENTRIES, &ring, 0) < 0) {
    close(s);
    return 5;
  }

  signal(SIGINT, sigint);
  atexit(cleanup);

  if (0 != (ret = setup_accept(&ring, &addr, &addrlen, s))) {
    return ret;
  }
  
  while (!do_terminate) {
    struct io_uring_cqe *cqe, mycqe;
    ret = io_uring_wait_cqe(&ring, &cqe);
    if (-EINTR == ret) {
      break;
    } else if (ret) {
      //printf("wait_cqe: %d\n", ret);
      return 8;
    }
    mycqe = *cqe;
    io_uring_cqe_seen(&ring, cqe);

    //fprintf(stderr, "evt: %llu\n", io_uring_cqe_get_data64(&mycqe));
    //if (io_uring_cqe_get_data64(&mycqe) >= 64) {
    //  fprintf(stderr, "evt fd: %d\n", ((struct promo_echo_user_data *)io_uring_cqe_get_data(&mycqe))->fd);
    //}
    switch(io_uring_cqe_get_data64(&mycqe)) {
    case 1:
      // accept
      int fd = mycqe.res;
      //printf("fd %d\n", fd);
      if (fd < 0) {
	continue;
      }
      int flags = fcntl(fd, F_GETFL, 0);
      if (flags == -1) {
	return 11;
      }
      fcntl(fd, F_SETFL, (flags | O_NONBLOCK));
      struct promo_echo_user_data *u = malloc(sizeof(*u));
      u->fd = fd;
      
      if (0 != (ret = setup_accept(&ring, &addr, &addrlen, s))) {
	return ret;
      }
      
      if (0 != (ret = setup_recv(&ring, u, 0))) {
	return ret;
      }

      break;
    default: {
      struct promo_echo_user_data *u = io_uring_cqe_get_data(&mycqe);
      ret = mycqe.res;
      switch(u->state) {
      default:
	assert(false);
	break;
      case RECV:
	if ((ret <= 0) && (ret != -EAGAIN)) {
	  if (0 != (ret = setup_close(&ring, u))) {
	    return ret;
	  }
	} else if (ret == -EAGAIN) {
	  // no data, it is only possible if we had full buffer
	  if (0 != (ret = setup_to(&ring, u))) {
	    return ret;
	  }
	} else /* ret > 0 */ {
	  // recv has read some data, need to send it back
	  assert(ret <= sizeof(u->data));
	  u->size = ret;
	  if (0 != (ret = setup_send(&ring, u))) {
	    return ret;
	  }
	}
	break;
      case SEND:
	if (ret < 0) {
	  if (0 != (ret = setup_close(&ring, u))) {
	    return ret;
	  }
	} else {
	  if (u->size == sizeof(u->data)) {
	    // Buffer is full, possibly there is more data from user
	    if (0 != (ret = setup_recv(&ring, u, MSG_DONTWAIT))) {
	      return ret;
	    }
	  } else {
	    if (0 != (ret = setup_to(&ring, u))) {
	      return ret;
	    }
	  }
	}
	break;
      case TIMEOUT:
	if (0 != (ret = setup_recv(&ring, u, 0))) {
	  return ret;
	}
	break;
      case CLOSE:
	free(u);
	break;
      }
    } }
    
  }

  return 0;
}
