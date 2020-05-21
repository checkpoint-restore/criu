#ifndef IMAGE_STREAMER_H
#define IMAGE_STREAMER_H

extern int img_streamer_init(const char *image_dir, int mode);
extern void img_streamer_finish(void);
extern int img_streamer_open(char *filename, int flags);

#endif /* IMAGE_STREAMER_H */
