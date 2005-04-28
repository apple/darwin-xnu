/* setupdialog : converts a RAW image file into the c structure that the
 * kernel panic ui system expects.
 *
 * to build: cc -o setupdialog setupdialog.c
*/

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>

#define RUN_MAX 32767

void create_numbers_file( FILE *stream, char *outfile );
unsigned int encode_rle(unsigned char * fileArr, unsigned int filePos, unsigned int quantity, unsigned char value);

void
usage(void) {
    printf("\nusage: setupdialog -i <image file> -oi <image output> -n <numbers file> -on <numbers output>\n");
    
    printf("\nYou can supply a panic image file, a numbers file, or both. Input files\n");
    printf("must be in RAW format where each pixel is represented by an index into the\n");
    printf("MacOS X system CLUT. The first %d bytes must be the width, height, and depth\n", 3 * sizeof(short));
    printf("(in that order, %d bytes each).\n", sizeof(short));

    printf("\nThe output files are generated C structures in the format the panic ui code\n");
    printf("expects (default output files are panic_image.c and rendered_numbers.c).\n\n");
}

int 
main( int argc, char *argv[] )
{
    int		next;
    char 	*file = NULL, *ptr, *out = NULL, *numsfile = NULL, *numsout = NULL;
    FILE *	stream, *out_stream;
    int *	data;
    short 	width = 0, height = 0, depth = 0;
    char	word[2];
    char	byte;
    unsigned int i, pixels, filePos;
    int		err;
    unsigned char *fileArr;
    unsigned char nextP;
    unsigned int count;
    int currP;
    int fd;
    int pairs_this_line;


    // pull apart the arguments
    for( next = 1; next < argc; next++ )
    {
        if (strcmp(argv[next], "-i") == 0) // image file (RAW/PICT?)
            file = argv[++next];
        else if (strcmp(argv[next], "-n") == 0) // numbers/chars image file (RAW)
            numsfile = argv[++next];
        else if (strcmp(argv[next], "-oi") == 0) // output file for image
            out = argv[++next];
        else if (strcmp(argv[next], "-on") == 0) // output file for numbers
            numsout = argv[++next];
	
	/* perhaps we should just let the user specify the W/H rather than require the header */
	/*
        else if (strcmp(argv[next], "-w") == 0) // image width (pixels)
            width = strtoul(argv[++next], &ptr, 0);
        else if (strcmp(argv[next], "-h") == 0) // image height (pixels)
            width = strtoul(argv[++next], &ptr, 0);
	*/
    }
    
    if (!(numsfile || file)) {
	usage();
	exit(1);
    }

    if (!numsfile) {
	printf("\nNo numbers file to process\n");
    } else {
        stream = fopen(numsfile, "r");
        if (!stream) {
            printf("bad nums infile.. bailing.\n");
            exit(1);
        }
        create_numbers_file( stream, numsout );
        fclose(stream);
    }
    
    if( file == NULL) {
        printf("\nNo image file to process\n");
        exit(1);
    }
    
    stream = fopen(file, "r");
    if (!stream) {
        printf("bad infile.. bailing.\n");
        exit(1);
    }
    
    printf("\nReading image file...\n");

    fread((void *) &width, sizeof(short), 1, stream);
    printf("got width: %d\n", width);
    fread((void *) &height, sizeof(short), 1, stream);
    printf("got height: %d\n", height);
    fread((void *) &depth, sizeof(short), 1, stream);
    printf("got depth: %d\n", depth);
    
    if (!(width && height && depth)) {
	printf("Invalid image file header (width, height, or depth is 0)\n");
	exit(1);
    }

    pixels = width * height;

    if (!(fileArr = (unsigned char *) malloc(pixels))) {
	printf("couldn't malloc fileArr (%d pixels)... bailing.\n", pixels);
	exit(1);
    }
    
    currP = -1;
    count = 0;
    filePos = 0; // position in the file we're writing out
    
    for (i=0; i < pixels; i++) {
        nextP = fgetc(stream);
        count++;
        if (nextP == currP) {
            if (count >= RUN_MAX) {
                    filePos += encode_rle(fileArr, filePos, count, (unsigned char) currP);
                    count = 0;
                    currP = -1;
            } 
        } else {
            if (currP != -1) {
                filePos += encode_rle(fileArr, filePos, count-1, (unsigned char) currP);
            }
            currP = nextP; // start a new run
            count = 1;
        }
    }
    
    // write out any run that was in progress
    if (count > 0) {
        filePos += encode_rle(fileArr, filePos, count, (unsigned char) currP);
    }	
    
    fclose( stream ); 

    // now, generate the c file
    
    if ( out == NULL)
        out = "panic_image.c";
    out_stream = fopen(out, "w");
    
    if(out_stream == NULL) {
        printf("couldn't open out file.. bailing\n");
        exit(1);
    }
    
    pairs_this_line = 0;
    
    fprintf( out_stream, "/* generated c file */\n\n");
    fprintf( out_stream, "static const struct {\n");
    fprintf( out_stream, "  unsigned int 	 pd_width;\n");
    fprintf( out_stream, "  unsigned int 	 pd_height;\n");
    fprintf( out_stream, "  unsigned int 	 bytes_per_pixel; /* 1: CLUT, 3:RGB, 4:RGBA */\n");
    fprintf( out_stream, "  unsigned char	 image_pixel_data[%#4.2x];\n", (filePos));

    fprintf( out_stream, "} panic_dialog = {\n");
    fprintf( out_stream, "\t%d, ", width);		/* panic dialog x */
    fprintf( out_stream, "%d, ", height);		/* panic dialog y */
    fprintf( out_stream, "1,\n");			/* bytes per pixel */
   
    for( i=0; i < filePos;) {
    	fprintf( out_stream, "0x%.2x,0x%.2x", fileArr[i], fileArr[i+1]);
	i+=2;
        pairs_this_line++;
        
        // if the first byte had a leading 1, this is a 3-byte encoding
        if ((fileArr[i-2] >> 7) == 1) {
            fprintf( out_stream, ",0x%.2x", fileArr[i++]);
	    pairs_this_line++;
        }
        
        if (i >= filePos) // this is the last element
            fprintf( out_stream, "\n};");
        else fprintf( out_stream, ", ");
       
        if(pairs_this_line > 8) {
            fprintf( out_stream, "\n");
            pairs_this_line = 0;
        }
    }
    
  
  fclose( out_stream );

  return 0;
}


/* Each number/char (0-f) has its own row in the pixmap array.
    When done, these rows each contain an RLE character.
    The image file is read row by row, so the individual characters
    must be constructed in the same way. The numPos array tracks the
    current position in each character's RLE array.
    */
void
create_numbers_file( FILE *stream, char *outfile )
{
    int		err;
    short	height, depth, totalwidth;
    int		numbers = 17;
    int         width[17] = {9,7,8,6,9,7,8,7,8,7,10,7,9,10,7,6,4};
    int		numPos[17] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; 
    
    int **pixmap;
    int		row, col, item, line=0, currWidth;
    int nextP, currP;
    int count, currNum;
    
    FILE	*out_stream;

    printf("\nReading numbers file...\n");
    fread((void *) &totalwidth, sizeof(short), 1, stream);
    printf("got width: %d\n", totalwidth);
    fread((void *) &height, sizeof(short), 1, stream);
    printf("got height: %d\n", height);
    fread((void *) &depth, sizeof(short), 1, stream);
    printf("got depth: %d\n", depth);
    
    if (!(width && height && depth)) {
	printf("Invalid numbers file header (width, height, or depth is 0)\n");
	return;
    }

    // allocate array to hold each number's RLE encoding (20 = 2xwidest width[i] value, 17 = num chars)
    pixmap = (int **) malloc( 17 * sizeof(int *) );
    for( item=0; item<17; item++)
        pixmap[item] = (int *) malloc( 2*width[item]*height*sizeof(int) );
    
    currP = -1;
    count = 0;
    currWidth = 0;
    currNum = 0;
    
    for( row=0; row < height; row++) {
        for( item=0; item < numbers; item++) {
            count = 0;
            currP = -1; // start each character fresh
            for( col=0; col < width[item]; col++) {
                nextP = fgetc( stream );
                if( nextP == currP) {
                    if( count == 127) { // probably never executed given the small widths
                        pixmap[item][numPos[item]] = count;
                        pixmap[item][numPos[item]+1] = currP;
                        numPos[item]+=2;
                        count = 0;
                        currP = -1;
                    } else count++; // add one to the current run
                } else {
                    if( currP != -1) {
                        pixmap[item][numPos[item]] = count; // currP was the end of the run
                        pixmap[item][numPos[item]+1] = currP;
                        numPos[item]+=2;
                    }
                    currP = nextP; // start a new run
                    count = 1;
                }
            }	
            // write out any run that was in progress
            if( count > 0) {
                pixmap[item][numPos[item]] = count;
                pixmap[item][numPos[item]+1] = currP;
                numPos[item]+=2;
            }
        }
    }
    
    // now, generate the c file
    
    if ( outfile == NULL)
        outfile = "rendered_numbers.c";
    out_stream = fopen(outfile, "w");
    
    if(out_stream == NULL) {
        printf("couldn't open numbers outfile.. bailing\n");
        exit(1);
    }
    
    fprintf( out_stream, " /* generated c file */\n\n");
    
    // iterate through all the numbers/chars
    for( item=0; item<numbers; item++)
    {
        fprintf( out_stream, "static const struct {\n");
        fprintf( out_stream, "  unsigned int 	 num_w;\n");
        fprintf( out_stream, "  unsigned int 	 num_h;\n");			
        fprintf( out_stream, "  unsigned char	 num_pixel_data[%#4.2x];\n", numPos[item]); // num elems
        item == 16 ? fprintf( out_stream, "} num_colon = {\n") : fprintf( out_stream, "} num_%x = {\n", item);
        fprintf( out_stream, "/* w */ %d,\n", width[item]);
        fprintf( out_stream, "/* h */ %d,\n", height);
        fprintf( out_stream, "/* pixel_data */ \n");
            
        for( col = 0; col < numPos[item];)
        {
            fprintf( out_stream, "0x%.2x,0x%.2x", pixmap[item][col], pixmap[item][col+1]);
            if (col == (numPos[item] - 2)) // this is the last element
                fprintf( out_stream, "\n};\n\n");
            else fprintf( out_stream, ", ");
            
            line+=pixmap[item][col];
            if( line >= width[item]) {
                fprintf( out_stream, "\n");
                line = 0;
            }
            col+=2;
        }
    }
    
  fclose( out_stream );
}


/* 	encode_rle applies a "modified-RLE encoding to a given image. The encoding works as follows:
        
        The quantity and value will be described by either two or three bytes. If the
        most significant bit of the first byte is a 0, then the next seven bits are
        the quantity (run-length) and the following 8 bits are the value (index into
        a clut, in this case). If the msb of the first byte is a 1, then the next 15 bits
        are the quantity and the following 8 are the value. Visually, the two possible
        encodings are: (q = quantity, v = value)
        
          Byte 1			   Byte 2		        Byte 3
  case 1: [ 0 q6 q5 q4 q3 q2 q1 q0 ]       [ v7 v6 v5 v4 v3 v2 v1 v0 ]  [ ]
  case 2: [ 1 q14 q13 q12 a11 q10 q9 q8 ]  [ q7 q6 q5 q4 q3 q2 q1 q0 ]  [ v7 v6 v5 v4 v3 v2 v1 v0 ]
*/


unsigned int
encode_rle(unsigned char * fileArr, unsigned int filePos, unsigned int quantity, unsigned char value)
{
    unsigned char single_mask = 0x00;
    unsigned char double_mask = 0x80;
    unsigned char slots_used = 0;
    
    if (quantity < 128) {
        fileArr[filePos] = single_mask | quantity;
        slots_used = 1;
    } else {
        fileArr[filePos] = double_mask | (quantity >> 8); // high 7 bits (plus mask)
        fileArr[filePos+1] = (unsigned char) quantity; // low 8 bits
        slots_used = 2;
    }
    
    fileArr[filePos+slots_used] = value;
    slots_used++;
    
    return slots_used;
}
