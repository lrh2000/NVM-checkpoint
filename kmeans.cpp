#include <unistd.h>

struct point_t
{
  double x;
  double y;
};

inline double operator ^(const point_t &a, const point_t &b)
{
  return (a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y);
}

inline point_t &operator +=(point_t &a, const point_t &b)
{
  a.x += b.x;
  a.y += b.y;
  return a;
}

inline point_t &operator /=(point_t &a, int b)
{
  a.x /= b;
  a.y /= b;
  return a;
}

static constexpr size_t N = 200000, K = 10;

static point_t points[N], centers[K];
static unsigned int center_of[N];
static unsigned int center_count[K];

static inline void checkpoint(void)
{
  asm volatile("ud2");
}

static void __attribute__ ((noinline)) find_center(void)
{
  for (size_t i = 0;i < N;++i)
  {
    double min = 1e100;
    unsigned int argmin = -1;
    for (size_t j = 0;j < K;++j)
    {
      auto now = points[i] ^ centers[j];
      if (now < min) {
        min = now;
        argmin = j;
      }
    }
    center_of[i] = argmin;
  }
}

static void __attribute__ ((noinline)) calc_center(void)
{
  for (size_t i = 0;i < K;++i)
  {
    centers[i] = (point_t) {0.0, 0.0};
    center_count[i] = 0;
  }

  for (size_t i = 0;i < N;++i)
  {
    centers[center_of[i]] += points[i];
    ++center_count[center_of[i]];
  }

  for (size_t i = 0;i < K;++i)
    if (center_count[i] > 0)
      centers[i] /= center_count[i];
}

static void __attribute__ ((noinline)) find_center_reversed(void)
{
  for (size_t i = N - 1;~i;--i)
  {
    double min = 1e100;
    unsigned int argmin = -1;
    for (size_t j = K - 1;~j;--j)
    {
      auto now = points[i] ^ centers[j];
      if (now < min) {
        min = now;
        argmin = j;
      }
    }
    center_of[i] = argmin;
  }
}

static void __attribute__ ((noinline)) calc_center_reversed(void)
{
  for (size_t i = K - 1;~i;--i)
  {
    centers[i] = (point_t) {0.0, 0.0};
    center_count[i] = 0;
  }

  for (size_t i = N - 1;~i;--i)
  {
    centers[center_of[i]] += points[i];
    ++center_count[center_of[i]];
  }

  for (size_t i = K - 1;~i;--i)
    if (center_count[i] > 0)
      centers[i] /= center_count[i];
}

static void kmeans(void)
{
  for (size_t i = K - 1;~i;--i)
    centers[i] = points[i * N / K];

  for (size_t i = 0;i < 60;++i)
  {
    checkpoint();
    if (true) {
      find_center_reversed();
      calc_center_reversed();
    } else {
      find_center();
      calc_center();
    }
  }
}

int main(void)
{
  // TODO: Load some example data.

  // checkpoint();
  kmeans();
  _exit(0);
}
