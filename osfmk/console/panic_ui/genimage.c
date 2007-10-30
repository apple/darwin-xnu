/* converts a QT RAW image file into the c structure that the
 * kernel panic ui system expects.
 *
 * to build: cc -o genimage genimage.c
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

int EncodeImage(
					unsigned char * data,
					int pixels,
					unsigned char * fileArr );
int decode_rle(
					unsigned char * dataPtr,
					unsigned int * quantity,
					unsigned int * depth,
					unsigned char ** value );
int findIndexNearMatch(
					unsigned int color24 );
unsigned char findIndexMatch(
					unsigned int color24 );
int convert24toGrey(
					unsigned char * data,
					unsigned int size );
int convert8toGrey(
					unsigned char * data,
					unsigned int size );
int convert8bitIndexto24(
					unsigned char * data,
					int height,
					int width,
					unsigned char ** dout );
int convert8bitIndexto8(
					unsigned char * data,
					int height,
					int width,
					unsigned char ** dout );
int convert24to8bitIndex(
					unsigned char * data,
					int height,
					int width,
					unsigned char ** dout );
unsigned int * CreateCLUTarry(
					unsigned char * raw_clut );
unsigned int *  ReplaceCLUT(
					char * iname );
void GenerateCLUT(
					char * oname );
void WriteQTRawFile(
					FILE * ostream,
					unsigned char * data,
					int height,
					int width,
					int depth,
					unsigned int size );
void CreateRawQTFont(
					void );
void CreateRawQTCLUT(
					int type );

#define offsetof(type, field) ((size_t)(&((type *)0)->field))

struct panicimage {
	unsigned int	pd_sum;
	unsigned int	pd_dataSize;
	unsigned int	pd_tag;
	unsigned short	pd_width;
	unsigned short	pd_height;
	unsigned char	pd_depth;
	unsigned char	pd_info_height;
	unsigned char	pd_info_color[2];
	unsigned char	data[];
};




void
usage( int type ) {
printf(
"\n"
"Usage:\n"
"\tgenimage -i <.qtif> [operands ...]\n\n"
"\tThe following operands are available\n\n"
"\t-h\t\tDisplay full help information\n"
"\t-i  <file>\tUse file containing QuickTime uncompressed raw image as\n"
"\t\t\tthe panic dialog (8 or 24 bit)\n"
"\t-o  <file>\tWrite the output as a compressed WHD RAW image suitable\n"
"\t\t\tfor loading into the kernel\n"
"\t-c  <file>\tUse file containing 256 RGB values for 8-bit indexed \n"
"\t\t\tlookups, overrides built-in appleClut8\n"
"\t-fg <color>\tForeground color of font used for panic information in\n"
"\t\t\t24-bits, default 0xFFFFFF (100%% white)\n"
"\t-bg <color>\tBackground color of font used for panic information in\n"
"\t\t\t24-bits, default 0x222222 (13%% white, dark gray)\n"
"\t-n  <lines>\tNumber of lines that have been reserved to display the\n"
"\t\t\tpanic information, must be at least 20\n"
"\n\tThese are useful options for testing\n"
"\t-io <file>\tUse <file> to override the default C source filename\n"
"\t-bw\t\tConvert the input image to shades of gray\n"
"\t-n24\t\tConvert an image from 8 bit to 24 bit mode before\n"
"\t\t\tprocessing\n"
"\t-n8\t\tDon't convert an image from 24 bit to 8 bit mode before \n"
"\t\t\tprocessing, default is to convert\n"
"\t-qt <file>\t(requires -i) Write QuickTime uncompressed raw .gtif\n"
"\t\t\tfile containing the input image in 8-bit format\n"
"\t-r\t\tCreate a Quicktime uncompressed image of the 8-bit\n"
"\t\t\tsystem CLUT named appleclut8.qtif <debugging>\n"
"\t-f\t\tCreate a Quicktime uncompressed image of the 8x16\n"
"\t\t\tbit panic info font named font.qtif <debugging>\n"
"\n\n" );
if ( type > 0 )
printf(
"\
This utility is used to convert a panic dialog from .qtif format, into\n\
one that is suitable for the kernel to display.  The .qtif image file\n\
can be in either 24 or 8 bit mode, but must be in an uncompressed raw\n\
format.  8 bit mode is preferred, as it requires no conversion to the\n\
colors that are contained in the CLUT.  If a color cannot be found in\n\
the CLUT, it will be converted to the nearest gray.  The default CLUT\n\
is the same as the system CLUT. If needed, this can be overridden by\n\
providing a new CLUT with the -c option.\n\
\n\
However, if you override the default CLUT.  The panic UI may not appear\n\
as you intended, when the systme is in 8 bit mode.  Colors that are not\n\
present in the active CLUT, will be converted to the nearest gray.\n\
\n\
The panic dialog must have a number of lines reserved at the bottom for\n\
displaying additional panic information.  The minimum number of lines\n\
is 20.  The font use to display this information needs to have the\n\
foreground and background colors defined.  The defaults are full white\n\
on dark gray.  This can be changed by using the -fg and/or -bg options to\n\
provide new 24 bit colors.  These colors must be contained in the CLUT.\n\
\n\
There are two possible output results.  The default is to create a C\n\
source file named panic_image.c that contains the panic image in a 8 bit\n\
modified RLE compressed format and the CLUT that was used to create the\n\
image.  The second possibility is to create a binary version of the same\n\
information by using the -o option.  This file can then be used to replace\n\
the panic dialog that is currently active in the kernel by using\n\
sysctl(KERN_PANIC_INFO).\n\
\n\n");
}


#include "appleclut8.h"
#include "../iso_font.c"

struct QTHeader {
	long	idSize;			/* total size of ImageDescription including extra data ( CLUTs and other per sequence data ) */
	long	cType;			/* 'raw '; what kind of codec compressed this data */
	long	resvd1;			/* reserved for Apple use */
	short	resvd2;			/* reserved for Apple use */
	short	dataRefIndex;		/* set to zero  */
	short	version;		/* which version is this data */
	short	revisionLevel;		/* what version of that codec did this */
	long	vendor;			/* whose  codec compressed this data */
	long	temporalQuality;	/* what was the temporal quality factor  */
	long	spatialQuality;		/* what was the spatial quality factor */
	short	width;			/* how many pixels wide is this data */
	short	height;			/* how many pixels high is this data */
	long	hRes;			/* horizontal resolution */
	long	vRes;			/* vertical resolution */
	long	dataSize;		/* if known, the size of data for this image descriptor */
	short	frameCount;		/* number of frames this description applies to */
	char	name[32];		/* name of codec ( in case not installed )  */
	short	depth;			/* what depth is this data (1-32) or ( 33-40 grayscale ) */
	short	clutID;			/* clut id or if 0 clut follows  or -1 if no clut */
} image_header;

static unsigned int mismatchClut[256];
static int nextmis = -1, neargrey = 0, cvt2grey = 0, exactmatch=0;
static int grey = 0, debug = 0, testfont = 0, testclut = 0;
static int convert = 8; // default is to convert image to 8 bit uncompressed .tgif
static unsigned char fg, bg;
unsigned int * panic_clut = NULL;
static char  * clutin = NULL;

union colors {
	unsigned int c24;
	unsigned char rgb[4];
	struct {
		unsigned char dummy;
		unsigned char red;
		unsigned char green;
		unsigned char blue;
	} clut;
};

int 
main( int argc, char *argv[] )
{
	char	*file = NULL;
	char	*out = NULL;
	char	*kraw = NULL;
	char	*qtraw = NULL;
	char	*clutout = NULL;
	char	*whdname = NULL;
	FILE *  stream, *out_stream;
	unsigned char * data;
	unsigned short	width = 0, height = 0;
	unsigned char	depth = 0, lines = 20;
	unsigned int i, pixels, sum, encodedSize, fg24= 0xFFFFFF, bg24=0x222222;
	unsigned char *fileArr;
	int chars_this_line, next, runindex;


	// pull apart the arguments
	for( next = 1; next < argc; next++ )
	{
		if (strcmp(argv[next], "-i") == 0) // image file in raw QT uncompressed format (.qtif)
			file = argv[++next];

		else if (strcmp(argv[next], "-o") == 0) // output file for WHD image
			kraw = argv[++next];
		else if (strcmp(argv[next], "-io") == 0) // output file for image
			out = argv[++next];

		else if (strcmp(argv[next], "-n") == 0) // numbers of reserved lines
			lines = atoi(argv[++next]);
		else if (strcmp(argv[next], "-fg") == 0) // foreground color in 24 bits
			sscanf(argv[++next], "%i", &fg24);
		else if (strcmp(argv[next], "-bg") == 0) // background color in 24 bits
			sscanf(argv[++next], "%i", &bg24);
		else if (strcmp(argv[next], "-c") == 0) // input file for clut
			clutin = argv[++next];
		else if (strcmp(argv[next], "-h") == 0) // display more help
			{ usage(1); exit(1); }

		// useful testing options 
		else if (strcmp(argv[next], "-co") == 0) // output file for generating appleClut8.h array included in this file
			clutout = argv[++next];
		else if (strcmp(argv[next], "-a8") == 0) // output file for testing system CLUT 8 in QT RAW (test)
			testclut = 8;
		else if (strcmp(argv[next], "-r") == 0) // output file for QT clut RAW (test)
			testclut = 1;
		else if (strcmp(argv[next], "-qt") == 0) // output file for QT RAW (test)
			qtraw = argv[++next];
		else if (strcmp(argv[next], "-bw") == 0) // use only shades of grey (test)
			grey = 1;
		else if (strcmp(argv[next], "-n8") == 0) // don't convert to 8 by default (test)
			convert = 0;
		else if (strcmp(argv[next], "-n24") == 0) // convert to 8 to 24 (test)
			convert = 24;
		else if (strcmp(argv[next], "-f") == 0) // test font (test)
			testfont = 1;
		else if (strcmp(argv[next], "-w") == 0) // read WHD raw file and output 8 bit tqif
			whdname = argv[++next];

		else if (strcmp(argv[next], "-debug") == 0) // verbose
			debug++;
	}

	if (!(file || clutout || testfont || testclut || whdname) ) {
		usage(0);
		exit(1);
	}

	printf("\n");

	panic_clut = appleClut8;

	if ( clutin )
	{
		panic_clut = ReplaceCLUT( clutin );
		printf("Built-in CLUT has been replaced with %s...\n", clutin);
	} else
	{
		if ( whdname )
			printf("Using CLUT from %s...\n", whdname);
		else
			printf("Using Built-in CLUT...\n");
	}

	if ( clutout )  
	{
		GenerateCLUT( clutout );
		printf("Created C source file of %s...\n", clutout);
	}

	fg = findIndexNearMatch(fg24);
	bg = findIndexNearMatch(bg24);

	if ( testclut )
		CreateRawQTCLUT(testclut);

	if ( testfont )
		CreateRawQTFont();

	// Begin to process the image

	if( file == NULL)
	{
		if ( whdname == NULL )
		{
			if ( debug) 
				printf("No image file was processed...\n\n");
			exit(0);
		}
	}


	printf("Verifing image file...\n");
	if ( file != NULL )
	{
		stream = fopen(file, "r");
		if (!stream) {
			fprintf(stderr, "Err: could not open .qtif image file.\n\n");
			exit(1);
		}
	
		{
			long	hdr_off;
			long	hdr_type;
	
			fread((void *) &hdr_off, sizeof(long), 1, stream);
			fread((void *) &hdr_type, sizeof(long), 1, stream);

			if ( hdr_type != 'idat' ) goto errQTimage;

			fseek(stream, hdr_off, SEEK_SET);
			fread((void *) &hdr_off, sizeof(long), 1, stream);
			fread((void *) &hdr_type, sizeof(long), 1, stream);

			if ( hdr_type != 'idsc' ) goto errQTimage;

			fread((void *) &image_header, sizeof(image_header), 1, stream);
			if ( image_header.cType != 'raw ' ) goto errQTimage;
			if (( image_header.depth != 8 ) && ( image_header.depth != 24 )) goto errQTimage;

			width = image_header.width;
			height = image_header.height;
			depth = image_header.depth;

			printf("Image info: width: %d height: %d depth: %d...\n", width, height, depth);
	
			if (!(width && height && depth)) {
				fprintf(stderr,"Err: Invalid image file header (width, height, or depth is 0)\n");
				exit(1);
			}
		}

		if ( !(data = (char *)malloc(image_header.dataSize))) {
			fprintf(stderr,"Err: Couldn't malloc file data (%ld bytes)... bailing.\n", image_header.dataSize);
			exit(1);
		}

		// Read the image data
		fseek(stream, 8, SEEK_SET);
		fread((void *) data, image_header.dataSize, 1, stream);
		fclose( stream ); 

		if ( kraw && image_header.depth == 24 )
		{
			fprintf(stderr, "Err: The WHD raw file (%s) will not be created when input in is millions of colors\n", kraw);
			kraw = NULL;
		}

		pixels = image_header.dataSize;

		if ( image_header.depth == 24 )
		{
			if ( grey == 1 )
				pixels = convert24toGrey( data, image_header.dataSize);

			if ( convert == 8 )
			{
				printf("Converting image file to 8 bit...\n");
				pixels = convert24to8bitIndex( data, height, width, &data );
				image_header.dataSize = pixels;
				depth = 1;
			} else
				depth = 3;
		} else {
			if ( grey == 1 )
				pixels = convert8toGrey( data, image_header.dataSize );
	
			if ( convert == 24 )
			{
				printf("Converting image file to 24 bit...\n");
				pixels = convert8bitIndexto24( data, height, width, &data );
				image_header.dataSize = pixels;
				depth = 3;
			} else
			{
				printf("Converting image file to 8 bit raw...\n");
				pixels = convert8bitIndexto8( data, height, width, &data );
				image_header.dataSize = pixels;
				depth = 1;
			}
		}   

		printf("Converted %d pixels%s...\n", pixels/depth, ((grey==1)?" to grayscale":""));
		if ( exactmatch > 0 )
			printf("Found %d color mathces in CLUT...\n", exactmatch);
		if ( cvt2grey > 0 )
			printf("Converted %d colors to gray...\n", cvt2grey);
		if ( neargrey > 0 )
			printf("Adjusted %d grays to best match...\n", neargrey);
		if ( nextmis > 0 )
			printf("Total of %d seperate color mismatches...\n", nextmis);
	}
	else
	{
		unsigned int pixels_out;
		struct panicimage image;

		stream = fopen(whdname, "r");
		if (!stream) {
			fprintf(stderr, "Err: could not open WHD raw image file.\n\n");
			exit(1);
		}

		fread(&image, sizeof(image), 1, stream);

		if ( image.pd_tag != 'RNMp' )
			goto errWHDimage;

		if ( image.pd_depth != 1 )
			goto errWHDimage;

		width = image.pd_width;
		height = image.pd_height;
		depth = image.pd_depth;

		printf("Image info: width: %d height: %d depth: %d...\n", image.pd_width, image.pd_height, image.pd_depth);

		if (!(width && height && depth)) {
			fprintf(stderr,"Err: Invalid image file header (width, height, or depth is 0)\n");
			exit(1);
		}

		if ( !(fileArr = (char *)malloc(image.pd_dataSize))) {
			fprintf(stderr,"Err: Couldn't malloc file data (%ld bytes)... bailing.\n", image.pd_dataSize);
			exit(1);
		}

		/* read the data into a buffer */
		fread(fileArr, image.pd_dataSize, 1, stream);
		fclose(stream);

		encodedSize = image.pd_dataSize - (256 * 3);

		for(sum=0,i=0; i<encodedSize; i++)
		{
			sum += fileArr[i];
			sum <<= sum&1;
		}

		if (debug) printf("WHD sum = %x\n", sum);

		if ( sum != image.pd_sum )
			goto errWHDimage;

		for(pixels=0,i=0; i<encodedSize;)
		{
			unsigned int quantity, depth;	
			unsigned char * value;

			i += decode_rle( &fileArr[i], &quantity, &depth, &value );
			pixels += quantity * depth;
		}

		if ( debug) printf("pixels = %d sum = %x\n", pixels, sum);
		if ( debug) printf("es = %d H*W = %d sum = %x\n", encodedSize, image.pd_height*image.pd_width, image.pd_sum);

		if ( !(data = (char *)malloc(pixels))) {
			fprintf(stderr,"Err: Couldn't malloc file data (%ld bytes)... bailing.\n", pixels);
			exit(1);
		}

		{
			unsigned int quantity, line, col, depth, sum;
			unsigned char * dataIn, * value;
			
			sum = 0;
			pixels_out = 0;
			dataIn = fileArr;
			quantity = 0;
			for (line=0; line < height; line++) {
				for (col=0; col < width; col++) {

					if ( quantity == 0 ) {
						dataIn += decode_rle( dataIn, &quantity, &depth, &value );
						i = 0;
						sum += quantity * depth;
					}
					data[pixels_out++] = value[i++];

					if ( i == depth )
					{
						i = 0;
						quantity--;
					}
				}
			}
			if (debug) printf("total Q*D = %d\n", sum);
		}

		if( pixels_out != pixels )
		{
			printf("Err: miscalclulated pixels %d pixels_out %d\n", pixels, pixels_out);
			exit(1);
		}

		panic_clut = CreateCLUTarry( &fileArr[image.pd_dataSize-(256*3)] );

		qtraw = "panic_image.qtif";
	}

	if ( qtraw )
	{
		FILE * ostream;

		if ( (ostream = fopen(qtraw, "wb")) == NULL ) {
			fprintf(stderr,"Err: Could not open output file %s.\n\n", qtraw);
			exit(1);
		}

		printf("Creating image %s in QuickTime No Compression %s %s format...\n", qtraw, 
						(depth==3)?"Millions of":"256", (grey==0)?"colors":"grays");

		WriteQTRawFile( ostream, data, height, width, depth, pixels );
		fclose(ostream);
	}

	if ( depth != 1 )
	{
		printf("Depth != 1 (8-bit), skipping writing output..\n");
		goto leaveOK;
	}

	printf("Encoding image file...\n");
	
	if (!(fileArr = (unsigned char *) malloc(pixels))) {
		fprintf(stderr,"Err: Couldn't malloc fileArr (%d pixels)... bailing.\n", pixels);
		exit(1);
	}

	encodedSize = EncodeImage( data, pixels, fileArr );
	if ( encodedSize >= pixels )
	{
		printf("Skipping encoding...\n");
	}

	for (sum=0,i=0; i<encodedSize; i++)
	{
		sum += fileArr[i];
		sum <<= sum&1;
	}

	// write raw image suitable for kernel panic dialog
	if ( kraw )
	{
		FILE * ostream;
		unsigned int tag;

		if ( (ostream = fopen(kraw, "wb")) == NULL ) {
			fprintf(stderr,"Err: Could not open output file %s.\n\n", kraw);
			exit(1);
		}

		printf("Writing to binary panic dialog file %s, which is suitable for loading into kernel...\n", kraw);

		tag = 'RNMp';	// Raw NMage for Panic dialog
		depth = 1;	// only CLUT is supported
	
		fwrite(&sum, sizeof(sum), 1, ostream);
		sum = encodedSize;
		encodedSize += (256*3);
		fwrite(&encodedSize, sizeof(encodedSize), 1, ostream);
		encodedSize = sum;
		fwrite(&tag, sizeof(tag), 1, ostream);
		fwrite(&width, sizeof(width), 1, ostream);
		fwrite(&height, sizeof(height), 1, ostream);
		fwrite(&depth, sizeof(depth), 1, ostream);
		fwrite(&lines, sizeof(lines), 1, ostream);
		fwrite(&fg, sizeof(fg), 1, ostream);
		fwrite(&bg, sizeof(bg), 1, ostream);
		fwrite(fileArr, encodedSize, 1, ostream);

		for ( i=0; i<256; i++)
		{
			union colors c;
			unsigned char arr[3];

			c.c24 = panic_clut[i];

			arr[0] = c.clut.red;
			arr[1] = c.clut.green;
			arr[2] = c.clut.blue;
			fwrite(arr, 3, 1, ostream);
		}
		fclose(ostream);
		if ( out == NULL ) goto leaveOK;
	}

	// it's ok to generate the c file
	
	if ( out == NULL ) out = "panic_image.c";
	out_stream = fopen(out, "w");
	
	if(out_stream == NULL) {
		fprintf(stderr,"Err: Couldn't open out file %s.\n\n", out);
		exit(1);
	}
	
	printf("Writing C source %s, suitable for including into kernel build...\n", out);
	
	fprintf( out_stream, "/* autogenerated with genimage.c using %s as image input */\n", file);
	{
		char * s = "the built-in appleClut8";
		if ( clutin )
			s = clutin;
		fprintf( out_stream, "/* and %s for the color look up table (CLUT) */\n\n", s);
	}
	
	fprintf( out_stream, "static const struct panicimage {\n");
	fprintf( out_stream, "\tunsigned int\tpd_sum;\n");
	fprintf( out_stream, "\tunsigned int\tpd_dataSize;\n");
	fprintf( out_stream, "\tunsigned int\tpd_tag;\n");
	fprintf( out_stream, "\tunsigned short\tpd_width;\n");
	fprintf( out_stream, "\tunsigned short\tpd_height;\n");
	fprintf( out_stream, "\tunsigned char\tpd_depth;\n");
	fprintf( out_stream, "\tunsigned char\tpd_info_height;\n");
	fprintf( out_stream, "\tunsigned char\tpd_info_color[2];\n");
	fprintf( out_stream, "\tunsigned char\tdata[];\n");

	fprintf( out_stream, "} panic_dialog_default = {\n\t");
	fprintf( out_stream, "0x%08x, ", sum);		/* panic dialog x */
	fprintf( out_stream, "0x%08x, ", encodedSize+(256*3));		/* panic dialog x */
	fprintf( out_stream, "0x%08x, ", 'RNMp');		/* panic dialog x */
	fprintf( out_stream, "%d, ", width);		/* panic dialog x */
	fprintf( out_stream, "%d, ", height);		/* panic dialog y */
	fprintf( out_stream, "%d, ", depth);		/* bytes per pixel */
	fprintf( out_stream, "%d, ", lines);		/* lines reserved for panic info */
	fprintf( out_stream, "0x%02x, ", fg);		/* font foreground color: indexed */
	fprintf( out_stream, "0x%02x, ", bg);		/* font background color: indexed */

	fprintf( out_stream, "\n");
   
	chars_this_line = 0;
	fprintf( out_stream, "{\n");

	for( i=0; i < encodedSize;)
	{
		chars_this_line += fprintf( out_stream, "0x%.2x,", fileArr[i++]);

		if (i >= encodedSize) // this is the last element
			break;

		if(chars_this_line >= 80) {
			fprintf( out_stream, "\n");
			chars_this_line = 0;
		}
	}


	if (debug)
	{
		printf("Encoded size = %d\n", encodedSize);
		printf("Decoded size = %d\n", pixels);
	}
	
	fprintf(out_stream, "\n\n");
	for ( i=0; i<256; i+=4)
	{
		union colors c;

		if ( (i % 16) == 0 ) fprintf(out_stream, "// %02X\n", i);
		c.c24 = panic_clut[i+0];
		fprintf(out_stream, "\t0x%02X,0x%02X,0x%02X, ", c.clut.red, c.clut.green, c.clut.blue);
		c.c24 = panic_clut[i+1];
		fprintf(out_stream, "0x%02X,0x%02X,0x%02X, ", c.clut.red, c.clut.green, c.clut.blue);
		c.c24 = panic_clut[i+2];
		fprintf(out_stream, "0x%02X,0x%02X,0x%02X, ", c.clut.red, c.clut.green, c.clut.blue);
		c.c24 = panic_clut[i+3];
		fprintf(out_stream, "0x%02X,0x%02X,0x%02X%s\n", c.clut.red, c.clut.green, c.clut.blue, ((i!=(256-4))?",":""));
	}

	fprintf(out_stream, "}\n");
	fprintf(out_stream, "};\n");
  
	fclose( out_stream );

leaveOK:
	printf("\n");
	return 0;

errQTimage:
	fprintf(stderr,"Err: Image must be in the QuickTime Raw Uncompressed Millions or 256 Colors format\n");
	exit(1);
errWHDimage:
	fprintf(stderr,"Err: Image must be in the WHD Raw 256 Colors format\n");
	exit(1);
}
  


#define RUN_MAX ((1<<20)-1)

union RunData {
	unsigned int i;
	unsigned char c[4];
};

unsigned int encode_rle(
		unsigned char * fileArr,
		unsigned int filePos,
		unsigned int quantity,
		union RunData * value,
		int depth);

int
compareruns( unsigned char * data, unsigned int * index, unsigned int max, union RunData * currP, int * depth )
{
	unsigned int i = *index;
	union RunData * nextP;
	static int retc = 0;

	if ( currP == NULL || data == NULL )
	{
		retc = 0;
		goto Leave;
	}

	if ( (*index+*depth) > max )
	{
		*depth = 1;
		retc = 0;
		goto Leave;
	}

	nextP = (union RunData *) &data[*index];

	if ( retc == 1 )
	{
		// check current data against current depth
		switch ( *depth )
		{
			case 1:
				if ( nextP->c[0] == currP->c[0] )
					goto Leave;
				break;
			case 2:
				if ( nextP->c[0] == currP->c[0] &&
				     nextP->c[1] == currP->c[1] )
					goto Leave;
				break;
			case 3:
				if ( nextP->c[0] == currP->c[0] &&
				     nextP->c[1] == currP->c[1] &&
				     nextP->c[2] == currP->c[2] )
					goto Leave;
				break;
			case 4:
				if ( nextP->c[0] == currP->c[0] &&
				     nextP->c[1] == currP->c[1] &&
				     nextP->c[2] == currP->c[2] &&
				     nextP->c[3] == currP->c[3] )
					goto Leave;
				break;
		}

		retc = 0;
		goto Leave;
	}

	// start of a new pattern match begine with depth = 1
	
	if ( (*index+6) <= max )
	{
		// We have at least 8 bytes left in the buffer starting from currP 
#if 1
		nextP = (union RunData *) &data[*index+3];
		if ( nextP->c[0] == currP->c[0] &&
		     nextP->c[1] == currP->c[1] &&
		     nextP->c[2] == currP->c[2] &&
		     nextP->c[3] == currP->c[3] )
		{
			// check if they are all the same value
			if ( currP->c[0] == currP->c[1] &&
			     currP->c[1] == currP->c[2] &&
			     currP->c[2] == currP->c[3] )
			{  // if so, leave at depth = 1
				retc = 1;
				*depth = 1;
				goto Leave;
			}

			if (debug>2) printf("Found 4 at %x\n", *index);
			retc = 1;
			*depth = 4;
			*index += 3;
			goto Leave;
		}

		nextP = (union RunData *) &data[*index+2];
		if ( nextP->c[0] == currP->c[0] &&
		     nextP->c[1] == currP->c[1] &&
		     nextP->c[2] == currP->c[2] )
		{
			// check if they are all the same value
			if ( currP->c[0] == currP->c[1] &&
			     currP->c[1] == currP->c[2] )
			{  // if so, leave at depth = 1
				retc = 1;
				*depth = 1;
				goto Leave;
			}

			if (debug>2) printf("Found 3 at %x\n", *index);
			retc = 1;
			*depth = 3;
			*index += 2;
			goto Leave;
		}

		nextP = (union RunData *) &data[*index+1];
		if ( nextP->c[0] == currP->c[0] &&
		     nextP->c[1] == currP->c[1] )
		{
			// check if they are all the same value
			if ( currP->c[0] == currP->c[1] )
			{  // if so, leave at depth = 1
				retc = 1;
				*depth = 1;
				goto Leave;
			}

			if (debug>2) printf("Found 2 at %x\n", *index);
			retc = 1;
			*depth = 2;
			*index += 1;
			goto Leave;
		}

#endif
		nextP = (union RunData *) &data[*index];
		
	} 

	if ( nextP->c[0] == currP->c[0] )
		retc = 1;
	else
		retc = 0;
	
Leave:

	if ( retc == 1 )
		*index += *depth;

	return retc;
}

int 
EncodeImage( unsigned char * data, int pixels, unsigned char * fileArr )
{
	union RunData * currP, * norunP ;
	int i, match, depth;
	unsigned int filePos, run, nomatchrun;

	currP = NULL;
	norunP = NULL;
	nomatchrun = 0;
	filePos = 0; // position in the file we're writing out
	run = 1;
	depth = 1;

	currP = (union RunData *)&data[0]; // start a new run
	for (i=1; i<pixels;)
	{
		if ( compareruns( data, &i, pixels, currP, &depth ) )
			run++;
		else
		{
			if ( (run*depth) > 2 )
			{
				unsigned char * p = (unsigned char *)norunP;

				if( nomatchrun )
				{
					while (nomatchrun)
					{
						int cnt;

						cnt = (nomatchrun > 127) ? 127 : nomatchrun;
						fileArr[filePos++] = cnt;
						nomatchrun -= cnt;
	
						while ( cnt-- )
							fileArr[filePos++] = *p++;
					}
				}

				filePos += encode_rle(fileArr, filePos, run, currP, depth);

				norunP = NULL;
			}
			else
			{
				nomatchrun+=run;
			}

			currP = (union RunData *)&data[i]; // start a new run

			if( norunP == NULL )
			{
				nomatchrun = 0;
				norunP = currP;
			}

			depth = 1;		// switch back to a single byte depth
			run = 1;		// thee is always at least one entry
			i++;			// point to next byte
		}
	}

	if( nomatchrun )
	{
		unsigned char * p = (unsigned char *)norunP;
		while (nomatchrun)
		{
			int cnt;

			cnt = (nomatchrun > 127) ? 127 : nomatchrun;
			fileArr[filePos++] = cnt;
			nomatchrun -= cnt;
	
			while ( cnt-- )
				fileArr[filePos++] = *p++;
		}
	}

	// write out any run that was in progress
	if (run > 0) {
		filePos += encode_rle(fileArr, filePos, run, currP, depth);
	}   
	
	return filePos;
}

/*  encode_rle applies a "modified-RLE encoding to a given image. The encoding works as follows:
		
	The quantity is described in the first byte.  If the MSB is zero, then the next seven bits
	are the quantity. If the MSB is set, bits 0-3 of the quantity are in the least significant bits.  
	If bit 5 is set, then the quantity is further described in the next byte, where an additional
	7 bits (4-10) worth of quantity will be found.  If the MSB of this byte is set, then an additional
	7 bits (11-17) worth of quantity will be found in the next byte. This repeats until the MSB of
	a quantity byte is zero, thus ending the chain.

	The value is described in the first byte.  If the MSB is zero, then the value is in the next byte.
	If the MSB is set, then bits 5/6 describe the number of value bytes following the quantity bytes.
	
	encodings are: (q = quantity, v = value, c = quantity continues)
		
               Byte 1	     Byte 2          Byte 3      Byte 4      Byte 5    Byte 6    Byte 7   Byte 8
  case 1: [ 0       q6-q0 ] [ v7-v0 ]
  case 2: [ 1 0 0 c q3-q0 ] [ c q10-q4 ] [ c q17-q11 ] [ q24-q18 ] [ v7-v0 ]
  case 3: [ 1 0 1 c q3-q0 ] [ c q10-q4 ] [ c q17-q11 ] [ q24-q18 ] [ v7-v0 ] [ v7-v0 ]
  case 4: [ 1 1 0 c q3-q0 ] [ c q10-q4 ] [ c q17-q11 ] [ q24-q18 ] [ v7-v0 ] [ v7-v0 ] [ v7-v0 ]
  case 5: [ 1 1 1 c q3-q0 ] [ c q10-q4 ] [ c q17-q11 ] [ q24-q18 ] [ v7-v0 ] [ v7-v0 ] [ v7-v0 ] [ v7-v0 ]
*/

unsigned int
encode_length(unsigned char * fileArr, unsigned int filePos, unsigned int quantity, unsigned int mask)
{
	unsigned char single_mask = 0x0F;
	unsigned char double_mask = 0x7F;
	unsigned int slots_used = 0;

	fileArr[filePos] = mask | (quantity & single_mask); // low bits (plus mask)
	slots_used++;

	if (quantity >>= 4)
	{
		fileArr[filePos++] |= 0x10;	// set length continuation bit
		fileArr[filePos] = quantity & double_mask;
		slots_used++;

		while (quantity >>= 7)
		{
			fileArr[filePos++] |= 0x80;	// set length continuation bit
			fileArr[filePos] = quantity & double_mask;
			slots_used++;
		}
	}
	
	return slots_used;
}


unsigned int
encode_rle(unsigned char * fileArr, unsigned int filePos, unsigned int quantity, union RunData * value, int depth)
{
	unsigned char single_mask = 0x0F;
	unsigned char double_mask = 0x7F;
	unsigned char slots_used = 0;
	

	switch ( depth )
	{
		case 1:
			slots_used += encode_length( fileArr, filePos, quantity, 0x80 );
			fileArr[filePos+slots_used++] = value->c[0];
			break;

		case 2:
			slots_used += encode_length( fileArr, filePos, quantity, 0xA0 );
			fileArr[filePos+slots_used++] = value->c[0];
			fileArr[filePos+slots_used++] = value->c[1];
			break;

		case 3:
			slots_used += encode_length( fileArr, filePos, quantity, 0xC0 );
			fileArr[filePos+slots_used++] = value->c[0];
			fileArr[filePos+slots_used++] = value->c[1];
			fileArr[filePos+slots_used++] = value->c[2];
			break;

		case 4:
			slots_used += encode_length( fileArr, filePos, quantity, 0xE0 );
			fileArr[filePos+slots_used++] = value->c[0];
			fileArr[filePos+slots_used++] = value->c[1];
			fileArr[filePos+slots_used++] = value->c[2];
			fileArr[filePos+slots_used++] = value->c[3];
			break;
	}
	
	return slots_used;
}

int
decode_rle( unsigned char * dataPtr, unsigned int * quantity, unsigned int * depth, unsigned char ** value )
{
	unsigned int mask;
	int i, runlen, runsize;

	i = 0;
	mask = dataPtr[i] & 0xF0;

	if ( mask & 0x80 )
	{
		runsize = ((mask & 0x60) >> 5) + 1;
		runlen = dataPtr[i++] & 0x0F;

		if ( mask & 0x10 )
		{
			int shift = 4;

			do
			{
				mask = dataPtr[i] & 0x80;
				runlen |= ((dataPtr[i++] & 0x7F) << shift);
				shift+=7;
			} while (mask);
		}
	} else
	{
		runlen = 1;
		runsize = dataPtr[i++];
	}

	*depth = runsize;
	*quantity = runlen;
	*value = &dataPtr[i];

	return i+runsize;
}

int
findIndexNearMatch( unsigned int color24 )
{
	union colors color8;
	union colors clut8;
	int isGrey = 0;

	color8.c24 = color24;

	if ( color8.clut.red == color8.clut.green && color8.clut.green == color8.clut.blue )
		isGrey = 1;

	if ( isGrey ) {
		int i;
		unsigned int bestIndex = 0, rel, bestMatch = -1;

		for (i=0; i<256; i++)
		{
			clut8.c24 = panic_clut[i];
			
			if ( clut8.clut.red != clut8.clut.green || clut8.clut.green != clut8.clut.blue )
				continue;

			if ( clut8.clut.red > color8.clut.red) continue;
			rel = abs(color8.clut.red - clut8.clut.red);
			if ( rel < bestMatch ) {
				bestMatch = rel;
				bestIndex = i;
			}
		}

		return bestIndex;
	}

	// we must have a non-grey color
	return -1;  
}

unsigned int
color24toGrey( unsigned int color24 )
{
	float R, G, B;
	float Grey;
	union colors c;
	unsigned char grey8;
	unsigned int grey24;

	c.c24 = color24;

	R = (c.clut.red & 0xFF) ;
	G = (c.clut.green & 0xFF) ;
	B = (c.clut.blue & 0xFF) ;

	Grey = (R*.30) + (G*.59) + (B*.11);
	grey8 = (unsigned char) ( Grey + .5);
	grey24 = (grey8<<16) | (grey8<<8) | grey8;
	return grey24;
}

int
convert24toGrey( unsigned char * data, unsigned int size )
{
	float R, G, B;
	float Grey;
	unsigned int grey8;
	int i24;


	for ( i24=0; i24<size; i24+=3)
	{
		R = ((data[i24+0]) & 0xFF) ;
		G = ((data[i24+1]) & 0xFF) ;
		B = ((data[i24+2]) & 0xFF) ;

		Grey = (R*.30) + (G*.59) + (B*.11);
		grey8 = (unsigned int) ( Grey + .5);

		data[i24+0] = grey8;
		data[i24+1] = grey8;
		data[i24+2] = grey8;
	}

	return size;
}

int
convert8toGrey( unsigned char * data, unsigned int size )
{
	int i;
	unsigned int c24;
	union colors c;

	for ( i=0; i<size; i++)
	{
		c.c24 = panic_clut[data[i]];
		c24 = color24toGrey( c.c24 );
		data[i] = findIndexMatch( c24 );
	}

	return size;
}

unsigned int
findColor24NearMatch( unsigned int color24 )
{
	union colors c, i_color;
	unsigned char d=0xff, d_red, d_green, d_blue, i, prim;
	static unsigned int last_c = -1, last_co = -1, last_p = -1;
	
	if ( last_c == color24 )
		return last_co;

	c.c24 = color24;

	if ( c.rgb[1] > c.rgb[2] && c.rgb[1] > c.rgb[3] )
		prim = 1;
	else if ( c.rgb[2] > c.rgb[1] && c.rgb[2] > c.rgb[3] )
		prim = 2;
	else if ( c.rgb[3] > c.rgb[1] && c.rgb[3] > c.rgb[2] )
		prim = 3;
	else if ( c.rgb[1] == c.rgb[2] && c.rgb[1] == c.rgb[3] )
		prim = 0;	// gray
	else if ( c.rgb[1] == c.rgb[2] )
		prim = 0x12;	// red green
	else if ( c.rgb[1] == c.rgb[3] )
		prim = 0x13;	// red blue
	else if ( c.rgb[2] == c.rgb[3] )
		prim = 0x23;	// green blue
	else
		printf("cannot tell color %06x\n", color24);

	last_c = color24;
	last_p = prim;

	if ( prim == 0 || prim > 3 )
	{
		last_co = -1;
		return last_co;
	}

#if 0
	for (i=0; i<256; i++)
	{
		
		break;	
	}
#endif

	return -1;	
}


unsigned char
findIndexMatch( unsigned int color24 )
{
	int i;
	unsigned char ri;
	static unsigned char last = 0;

retry:
	if ( panic_clut[last] == color24 )
	{
		exactmatch++;
		return last;
	}

	for (i=0; i<256; i++)
	{
		if ( panic_clut[i] == color24 ) {
			last = i;
			exactmatch++;
			return last;
		}
	}

	if ( nextmis == -1 ) {
		for (i=0; i<256; i++) mismatchClut[i] = -1;
		nextmis = 0;
	}

	i = findIndexNearMatch(color24);

	if ( i == -1 )  // found a color that is not grey
	{
		unsigned int colormatch = findColor24NearMatch( color24 );

		if ( colormatch == -1 )		// cannot convert color
		{
			cvt2grey++;
			if (debug>1) printf("color %06X not matched at all\n", color24);
			color24 = color24toGrey(color24);
			if (debug>1) printf("now grey %06X\n", color24);
		}
		else
			color24 = colormatch;

		goto retry;
	}

	if (debug>1) printf("color %06X now matched at %x\n", color24, i);

	ri = i;

	neargrey++;

	// keep track of missed repeats 
	for ( i=0; i<nextmis; i++)
		if ( mismatchClut[i] == color24 )
			return ri;

	if ( debug) printf("closest match for %06X is at index %d %06X\n", color24, ri, panic_clut[ri]);
	if ( nextmis < 256 )
		mismatchClut[nextmis++] = color24;

	if ( debug && (nextmis >= 256) )
	{
		fprintf(stderr,"Err: Too many color mismatches detected with this CLUT\n");
		exit(1);
	} 

	return ri;
}

/*
 * Convert 24 bit mode to 8 bit.  We do not do any alignment conversions
 */

int
convert24to8bitIndex( unsigned char * data, int height, int width, unsigned char ** dout )
{
	unsigned int row, col, i, i24, i8, size;
	unsigned char index;
	unsigned char * ddata;
	union colors color24;

	size = height * width;

	ddata = (unsigned char *) calloc( size, 1);

	for (i24=0,i8=0,row=0; row<height; row++)
	{
		for (col=0; col<width; col++)
		{
			color24.clut.red = data[i24++];
			color24.clut.green = data[i24++];
			color24.clut.blue = data[i24++];

			index = findIndexMatch( color24.c24 );
			ddata[i8++] = index;
		}
	}

	* dout = ddata;

	return (i8);
}

/*
 * Convert 8 bit mode to 8 bit, We have to strip off the alignment bytes
 */

int
convert8bitIndexto8( unsigned char * data, int height, int width, unsigned char ** dout )
{
	unsigned int row, col, i, i8, size, adj;
	unsigned char index;
	unsigned char * ddata;
	union colors color24;

	adj=(4-(width%4))%4;	// adjustment needed to strip off the word alignment padding
	size = height * width;
	ddata = (unsigned char *) calloc( size, 1);

	for (i8=0,row=0; row<height; row++)
	{
		for (col=0; col<width; col++)
		{
			index = *data++;
			color24.c24 = panic_clut[index];
			index = findIndexMatch( color24.c24 );
			ddata[i8++] = index;
		}

		for (i=0; i<adj; i++)
			data++;
	}

	* dout = ddata;

	return (i8);
}
/*
 * Convert 8 bit mode to 24 bit, We have to strip off the alignment bytes
 */

int
convert8bitIndexto24( unsigned char * data, int height, int width, unsigned char ** dout )
{
	unsigned int row, col, i, i24, i8, size, adj;
	unsigned char index;
	unsigned char * ddata;
	union colors color24;

	adj=(4-(width%4))%4;	// adjustment needed to strip off the word alignment padding
	size = height * width;
	ddata = (unsigned char *) calloc( size, 3);

	for (i24=0,i8=0,row=0; row<height; row++)
	{
		for (col=0; col<width; col++)
		{
			index = data[i8++];
			color24.c24 = panic_clut[index];
		
			ddata[i24++] = color24.clut.red;
			ddata[i24++] = color24.clut.green;
			ddata[i24++] = color24.clut.blue;
		}

		for (i=0; i<adj; i++)
			i8++;
	}

	* dout = ddata;

	return (i24);
}


unsigned int *
CreateCLUTarry( unsigned char * raw_clut )
{
	unsigned int * new_clut, index, i;

	new_clut = (unsigned int *) calloc(256, sizeof(unsigned int));
	for ( index=0,i=0; i<256; index+=3,i++ )
		new_clut[i] = (raw_clut[index] << 16) | (raw_clut[index+1] << 8) | raw_clut[index+2];

	return new_clut;
}


unsigned int *
ReplaceCLUT( char * iname )
{
	FILE  * stream;
	unsigned char * raw_clut;
	unsigned int * new_clut, index, i;

	if ( (stream = fopen(iname, "rb")) == NULL ) {
		fprintf(stderr,"Err: Could not open input clut file %s.\n\n", iname);
		exit(1);
	}

	raw_clut = (char *) calloc(256, 3);
	fread(raw_clut, 256, 3, stream);
	fclose(stream);

	new_clut = CreateCLUTarry( raw_clut );

	free(raw_clut);
	return new_clut;
}


void
GenerateCLUT( char * oname )
{
	FILE  * ostream;
	int i;


	if ( (ostream = fopen(oname, "w")) == NULL ) {
		fprintf(stderr,"Err: Could not open output clut file %s.\n\n", oname);
		exit(1);
	}

	printf("Generating new CLUT array named %s\n", oname);
	fprintf(ostream, "// This Clut was generated from %s\n", (clutin)?clutin:"built-in appleClut8");
	fprintf(ostream, "unsigned int appleClut8[256] = {\n");
	for ( i=0; i<256; i+=8)
	{
		if ( (i % 16) == 0 ) fprintf(ostream, "// %02X\n", i);
		fprintf(ostream, "\t0x%06X, 0x%06X, 0x%06X, 0x%06X, 0x%06X, 0x%06X, 0x%06X, 0x%06X%s\n",
				panic_clut[i+0], panic_clut[i+1], panic_clut[i+2], panic_clut[i+3],
				panic_clut[i+4], panic_clut[i+5], panic_clut[i+6], panic_clut[i+7], ((i!=(256-8))?",":""));
	}
	fprintf(ostream, "};\n");
	fclose(ostream);
}

void
WriteQTRawFile( FILE * ostream, unsigned char * data, int height, int width, int depth, unsigned int size )
{
	unsigned int i, adj, csize, tmp, col, line;
	

	if ( depth == 1)
		adj=(4-(width%4))%4;	// adjustment needed to add the word alignment padding
	else
		adj = 0;

	csize = height*depth*(width+adj);

	if( debug && csize != size )
		printf("Adjusted Computed size (%d=H*W*D) to account to account for word alignment %d(%d)\n", size,csize,csize-size);

	tmp = csize + ( 2 * sizeof(unsigned int) );
	fwrite(&tmp, sizeof(unsigned int), 1, ostream);

	tmp = 'idat';
	fwrite(&tmp, sizeof(unsigned int), 1, ostream);

	if ( depth == 1)
	{
		for (line=0; line<height; line++)
		{
			for (col=0; col<width; col++)
				fwrite(data++, 1, 1, ostream);

			for (i=0; i<adj; i++)
				fwrite(&data[-1], 1, 1, ostream);
		}
	} else
			fwrite(data, csize, 1, ostream);

	tmp = 0x5e;
	fwrite(&tmp, sizeof(unsigned int), 1, ostream);
	tmp = 'idsc';
	fwrite(&tmp, sizeof(unsigned int), 1, ostream);
	
	image_header.idSize = sizeof(image_header) - 2;
	image_header.cType = 'raw '; 
	image_header.dataRefIndex = 0;
	image_header.version = 1;
	image_header.revisionLevel = 1;
	image_header.vendor = 'appl';
	image_header.temporalQuality = 0;
	image_header.spatialQuality = 1024-1;
	image_header.width = width;
	image_header.height = height;
	image_header.hRes = 72 << 16;
	image_header.vRes =  72 << 16;
	image_header.dataSize = csize;
	image_header.frameCount = 1;
	strlcpy(image_header.name, " None", sizeof(image_header.name)); 
	image_header.name[0] = 4;
	image_header.depth = depth*8;
	image_header.clutID = (depth==1) ? 8 : -1;
	
	fwrite(&image_header, sizeof(image_header)-2, 1, ostream);
}


void
CreateRawQTCLUT( int type )
{
	FILE  * ostream;
	char * name;
	unsigned char * raw_clut, * p;
	int row, i;
	int H=32, W=32, D;

	if ( type == 8 )
	{
		name = "appleclut8.qtif";
		D = 1;
	}
	else
	{
		name = "unknownclut.qtif";
		D = 3;
	}

	if ( (ostream = fopen(name, "wb")) == NULL ) {
		fprintf(stderr,"Err: Could not open output index file %s.\n\n", name);
		exit(1);
	}

	raw_clut = (unsigned char *) malloc(H*W*D*256);

	for (p=raw_clut, row=0; row<H; row++)
	{
		for (i=0; i<256; i++)
		{
			int j;
			union colors c;

			if ( D == 3 )
				c.c24 = panic_clut[i];

			for (j=0; j<W; j++)
			{
				if ( D == 1 )
					*p++ = i; 
				else
				{
					*p++ = c.clut.red;
					*p++ = c.clut.green;
					*p++ = c.clut.blue;
				}
			}
		}
	}
	WriteQTRawFile( ostream, (unsigned char *) raw_clut, H, 256*W, D, H*256*W*D );

	fclose(ostream);
}


void
CreateRawQTFont( void )
{
	FILE  * ostream;
	unsigned char fonts[16][256][8];
	int row, i;

	if ( (ostream = fopen("font.qtif", "wb")) == NULL ) {
		fprintf(stderr,"Err: Could not open output index file %s.\n\n", "font.qtif");
		exit(1);
	}

	for (row=0; row<16; row++)
	{
		for (i=0; i<256; i++)
		{
			int j;
			unsigned char * c;
			unsigned char bits;

			c = &iso_font[i*16];
			bits = c[row];
			for (j=7; j>=0; j--)
			{
				if ( bits & 0x80)
					fonts[row][i][j] = fg;
				else
					fonts[row][i][j] = bg;
				bits <<= 1;
			}
		}
	}

	WriteQTRawFile( ostream, (unsigned char *) fonts, 16, 256*8, 1, 16*256*8 );
	fclose(ostream);
}
