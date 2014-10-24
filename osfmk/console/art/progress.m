//
//cc progress.m -framework AppKit -Wall; ./a.out >/tmp/xx.c; cc /tmp/xx.c -Wall; cat /tmp/xx.c 

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <stdlib.h>
#import <stdint.h>
#include <getopt.h>
#import <string.h>


#define MAX_COLORS 256

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
} pixel_t;

static uint32_t clut_size = 0;
static pixel_t clut[MAX_COLORS];

static uint8_t 
lookup_color(uint8_t r, uint8_t g, uint8_t b)
{
    unsigned int i;

    for (i = 0; i < clut_size; i++) {
        if (clut[i].r == r &&
            clut[i].g == g &&
            clut[i].b == b) {
          return i;
        }
    }
    if (clut_size >= MAX_COLORS) {
        printf("Image must have no more than 256 unique pixel colors\n");
        exit(1);
    }
    clut[clut_size].r = r;
    clut[clut_size].g = g;
    clut[clut_size].b = b;
  
  return (uint8_t)clut_size++;;
}

void print_buffer (uint8_t * buffer, size_t width, size_t height, size_t row)
{
  printf("{");
  for (int y = 0; y < height; y++)
  {
    printf("\n    ");
    for (int x = 0; x < width; x++)
    {  
	printf("0x%02x,", buffer[x + y*row]);
    }
  }
  printf("\n}");
}

int onefile(const char * filename, int w, int h)
{
    int       size;
    uint8_t   color;
  
    FILE *file;
    if ((file = fopen(filename, "r")) == NULL) {
        fclose(file);
        printf ("ERROR!!! can not open resource file [%s]\n", filename);
        return 1;
    }
    fclose(file);
  
    NSString* filePath = [NSString stringWithUTF8String:filename];
    NSData* fileData = [NSData dataWithContentsOfFile:filePath];
    NSBitmapImageRep* bitmapImageRep = [[NSBitmapImageRep alloc] initWithData:fileData];
    NSSize imageSize = [bitmapImageRep size];
  
    size_t image_length = (int)imageSize.width * (int)imageSize.height;
    uint8_t* uncompressed_color_buffer = malloc(image_length);
    uint8_t* uncompressed_alpha_buffer = malloc(image_length);

    bzero(clut, sizeof(clut));
  
    clut_size = 0;
    size = 0;
  
    for (int y = 0; y < imageSize.height; y++) {
      for (int x = 0; x < imageSize.width; x++) {
        NSUInteger pixel[4] = {};
        [bitmapImageRep getPixel:pixel atX:x y:y];

        color = lookup_color((uint8_t)pixel[0],
                             (uint8_t)pixel[1],
                             (uint8_t)pixel[2]);

	assert(color <= 1);
	uint8_t alpha = pixel[3];
	assert((alpha != 0) == color);

	alpha = 255 - alpha;
      
        uncompressed_color_buffer[size] = color;
        uncompressed_alpha_buffer[size] = alpha;
        size++;
      }
    }

    assert(clut_size == 2);
    assert(clut[0].r == 0);
    assert(clut[0].g == 0);
    assert(clut[0].b == 0);
    assert(clut[1].r == 0xff);
    assert(clut[1].g == 0xff);
    assert(clut[1].b == 0xff);

    printf("\n");

    assert(w <= imageSize.width);
    assert(h <= imageSize.height);
 
    print_buffer (uncompressed_alpha_buffer, w, h, imageSize.width);
  
    if (uncompressed_color_buffer != NULL) {
      free (uncompressed_color_buffer);
    }
    if (uncompressed_alpha_buffer != NULL) {
      free (uncompressed_alpha_buffer);
    }
  
    return 0;
}


int main (int argc, char * argv[])
{
   printf("#include <stdint.h>\n\n");


   printf("\nstatic const unsigned char progressmeter_leftcap1x[2][%d * %d] = {", 9, 18);
   onefile("ProgressBarFullLeftEndCap.png", 9, 18);
   printf(",");
   onefile("ProgressBarEmptyLeftEndCap.png", 9, 18);
   printf("};\n");

   printf("\nstatic const unsigned char progressmeter_leftcap2x[2][4 * %d * %d] = {", 9, 18);
   onefile("ProgressBarFullLeftEndCap@2x.png", 2*9, 2*18);
   printf(",");
   onefile("ProgressBarEmptyLeftEndCap@2x.png", 2*9, 2*18);
   printf("};\n");

   printf("\nstatic const unsigned char progressmeter_middle1x[2][%d * %d] = {", 1, 18);
   onefile("ProgressBarFullMiddle.png", 1, 18);
   printf(",");
   onefile("ProgressBarEmptyMiddle.png", 1, 18);
   printf("};\n");

   printf("\nstatic const unsigned char progressmeter_middle2x[2][2 * %d * %d] = {", 1, 18);
   onefile("ProgressBarFullMiddle@2x.png", 1, 2*18);
   printf(",");
   onefile("ProgressBarEmptyMiddle@2x.png", 1, 2*18);
   printf("};\n");

   printf("\nstatic const unsigned char progressmeter_rightcap1x[2][%d * %d] = {", 9, 18);
   onefile("ProgressBarFullRightEndCap.png", 9, 18);
   printf(",");
   onefile("ProgressBarEmptyRightEndCap.png", 9, 18);
   printf("};\n");

   printf("\nstatic const unsigned char progressmeter_rightcap2x[2][4 * %d * %d] = {", 9, 18);
   onefile("ProgressBarFullRightEndCap@2x.png", 2*9, 2*18);
   printf(",");
   onefile("ProgressBarEmptyRightEndCap@2x.png", 2*9, 2*18);
   printf("};\n");


}

