#include "WKdm.h"

/***********************************************************************
 *                   THE PACKING ROUTINES
 */

/* WK_pack_2bits()
 * Pack some multiple of four words holding two-bit tags (in the low
 * two bits of each byte) into an integral number of words, i.e.,
 * one fourth as many.  
 * NOTE: Pad the input out with zeroes to a multiple of four words!
 */
static WK_word*
WK_pack_2bits(WK_word* source_buf,
              WK_word* source_end,
	      WK_word* dest_buf) {

   register WK_word* src_next = source_buf;
   WK_word* dest_next = dest_buf;
  
   while (src_next < source_end) {
      register WK_word temp = src_next[0];
      temp |= (src_next[1] << 2);
      temp |= (src_next[2] << 4);
      temp |= (src_next[3] << 6);
    
      dest_next[0] = temp;
      dest_next++;     
      src_next += 4;
   }
  
   return dest_next;

}

/* WK_pack_4bits()
 * Pack an even number of words holding 4-bit patterns in the low bits
 * of each byte into half as many words.
 * note: pad out the input with zeroes to an even number of words!
 */

static WK_word*
WK_pack_4bits(WK_word* source_buf,
	      WK_word* source_end,
	      WK_word* dest_buf) {
   register WK_word* src_next = source_buf;
   WK_word* dest_next = dest_buf;
  
   /* this loop should probably be unrolled */
   while (src_next < source_end) {
     register WK_word temp = src_next[0];
     temp |= (src_next[1] << 4);
    
     dest_next[0] = temp;
     dest_next++;     
     src_next += 2;
   }

   return dest_next;

}

/* pack_3_tenbits()
 * Pack a sequence of three ten bit items into one word.
 * note: pad out the input with zeroes to an even number of words!
 */
static WK_word*
WK_pack_3_tenbits(WK_word* source_buf,
		  WK_word* source_end,
		  WK_word* dest_buf) {

   register WK_word* src_next = source_buf;
   WK_word* dest_next = dest_buf;
  
   /* this loop should probably be unrolled */
   while (src_next < source_end) {
      register WK_word temp = src_next[0];
      temp |= (src_next[1] << 10);
      temp |= (src_next[2] << 20);
    
      dest_next[0] = temp;
      dest_next++;     
      src_next += 3;
   }

   return dest_next;

}

/***************************************************************************
 *  WKdm_compress()---THE COMPRESSOR
 */

unsigned int
WKdm_compress (WK_word* src_buf,
               WK_word* dest_buf,
	       unsigned int num_input_words)
{
  DictionaryElement dictionary[DICTIONARY_SIZE];

  /* arrays that hold output data in intermediate form during modeling */
  /* and whose contents are packed into the actual output after modeling */

  /* sizes of these arrays should be increased if you want to compress
   * pages larger than 4KB
   */
  WK_word tempTagsArray[300];         /* tags for everything          */
  WK_word tempQPosArray[300];         /* queue positions for matches  */
  WK_word tempLowBitsArray[1200];     /* low bits for partial matches */

  /* boundary_tmp will be used for keeping track of what's where in
   * the compressed page during packing
   */
  WK_word* boundary_tmp;

  /* Fill pointers for filling intermediate arrays (of queue positions
   * and low bits) during encoding.
   * Full words go straight to the destination buffer area reserved
   * for them.  (Right after where the tags go.)
   */
  WK_word* next_full_patt;
  char* next_tag = (char *) tempTagsArray;
  char* next_qp = (char *) tempQPosArray;
  WK_word* next_low_bits = tempLowBitsArray;

  WK_word* next_input_word = src_buf;
  WK_word* end_of_input = src_buf + num_input_words;

  PRELOAD_DICTIONARY;

  next_full_patt = dest_buf + TAGS_AREA_OFFSET + (num_input_words / 16);

#ifdef WK_DEBUG
  printf("\nIn WKdm_compress\n");
  printf("About to actually compress, src_buf is %u\n", src_buf);
  printf("dictionary is at %u\n", dictionary);
  printf("dest_buf is %u next_full_patt is %u\n", dest_buf, next_full_patt);
  fflush(stdout);
#endif

  while (next_input_word < end_of_input)
  {
     WK_word *dict_location;
     WK_word dict_word;
     WK_word input_word = *next_input_word;

     /* compute hash value, which is a byte offset into the dictionary,
      * and add it to the base address of the dictionary. Cast back and
      * forth to/from char * so no shifts are needed
      */
     dict_location =
       (WK_word *)
       (((char*) dictionary) + HASH_TO_DICT_BYTE_OFFSET(input_word));

     dict_word = *dict_location;

     if (input_word == dict_word)
     {
        RECORD_EXACT(dict_location - dictionary); 
     }
     else if (input_word == 0) {
        RECORD_ZERO;
     }
     else
     {
        WK_word input_high_bits = HIGH_BITS(input_word);
        if (input_high_bits == HIGH_BITS(dict_word)) {
	  RECORD_PARTIAL(dict_location - dictionary, LOW_BITS(input_word));
          *dict_location = input_word;
        }
        else {
	  RECORD_MISS(input_word);
            *dict_location = input_word;
        }
     }
     next_input_word++;
  }

#ifdef WK_DEBUG
  printf("AFTER MODELING in WKdm_compress()\n");  fflush(stdout);
  printf("tempTagsArray holds %u bytes\n",
         next_tag - (char *) tempTagsArray);
  printf("tempQPosArray holds %u bytes\n",
         next_qp - (char *) tempQPosArray);
  printf("tempLowBitsArray holds %u bytes\n",
         (char *) next_low_bits - (char *) tempLowBitsArray);

  printf("next_full_patt is %p\n",
          next_full_patt);

  printf(" i.e., there are %u full patterns\n",
     next_full_patt - (dest_buf + TAGS_AREA_OFFSET + (num_input_words / 16)));
  fflush(stdout);

  { int i;
    WK_word *arr =(dest_buf + TAGS_AREA_OFFSET + (num_input_words / 16));

    printf("  first 20 full patterns are: \n");
    for (i = 0; i < 20; i++) {
      printf(" %d", arr[i]);
    }
    printf("\n");
  }
#endif

  /* Record (into the header) where we stopped writing full words,
   * which is where we will pack the queue positions.  (Recall
   * that we wrote the full words directly into the dest buffer
   * during modeling.
   */

  SET_QPOS_AREA_START(dest_buf,next_full_patt);

  /* Pack the tags into the tags area, between the page header
   * and the full words area.  We don't pad for the packer
   * because we assume that the page size is a multiple of 16.
   */     

#ifdef WK_DEBUG
  printf("about to pack %u bytes holding tags\n", 
         next_tag - (char *) tempTagsArray);

  { int i;
    char* arr = (char *) tempTagsArray;

    printf("  first 200 tags are: \n");
    for (i = 0; i < 200; i++) {
      printf(" %d", arr[i]);
    }
    printf("\n");
  }
#endif

  boundary_tmp = WK_pack_2bits(tempTagsArray,
		               (WK_word *) next_tag,
			       dest_buf + HEADER_SIZE_IN_WORDS);

#ifdef WK_DEBUG  
    printf("packing tags stopped at %u\n", boundary_tmp);
#endif
  
  /* Pack the queue positions into the area just after
   * the full words.  We have to round up the source
   * region to a multiple of two words.
   */

  {
    unsigned int num_bytes_to_pack = next_qp - (char *) tempQPosArray;
    unsigned int num_packed_words = (num_bytes_to_pack + 7) >> 3; // ceil((double) num_bytes_to_pack / 8);
    unsigned int num_source_words = num_packed_words * 2;
    WK_word* endQPosArray = tempQPosArray + num_source_words;

    /* Pad out the array with zeros to avoid corrupting real packed
       values. */
    for (; /* next_qp is already set as desired */
	 next_qp < (char*)endQPosArray;
	 next_qp++) {
      *next_qp = 0;
    }

#ifdef WK_DEBUG    
    printf("about to pack %u (bytes holding) queue posns.\n",
           num_bytes_to_pack);
    printf("packing them from %u words into %u words\n",
           num_source_words, num_packed_words);
    printf("dest is range %u to %u\n",
           next_full_patt, next_full_patt + num_packed_words);
    { int i;
      char *arr = (char *) tempQPosArray;
      printf("  first 200 queue positions are: \n");
      for (i = 0; i < 200; i++) {
        printf(" %d", arr[i]);
      }
      printf("\n");
    }
#endif
    
    boundary_tmp = WK_pack_4bits(tempQPosArray,
			         endQPosArray,
				 next_full_patt);
#ifdef WK_DEBUG
     printf("Packing of queue positions stopped at %u\n", boundary_tmp);
#endif // WK_DEBUG

    /* Record (into the header) where we stopped packing queue positions,
     * which is where we will start packing low bits.
     */
    SET_LOW_BITS_AREA_START(dest_buf,boundary_tmp);

  }

  /* Pack the low bit patterns into the area just after
   * the queue positions.  We have to round up the source
   * region to a multiple of three words.
   */

  {
    unsigned int num_tenbits_to_pack =
      next_low_bits - tempLowBitsArray;
    unsigned int num_packed_words = (num_tenbits_to_pack + 2) / 3; //ceil((double) num_tenbits_to_pack / 3);
    unsigned int num_source_words = num_packed_words * 3;
    WK_word* endLowBitsArray = tempLowBitsArray + num_source_words;

    /* Pad out the array with zeros to avoid corrupting real packed
       values. */

    for (; /* next_low_bits is already set as desired */
	 next_low_bits < endLowBitsArray;
	 next_low_bits++) {
      *next_low_bits = 0;
    }

#ifdef WK_DEBUG
	  printf("about to pack low bits\n");
          printf("num_tenbits_to_pack is %u\n", num_tenbits_to_pack);
          printf("endLowBitsArray is %u\n", endLowBitsArray);
#endif
    
    boundary_tmp = WK_pack_3_tenbits (tempLowBitsArray,
		                      endLowBitsArray,
				      boundary_tmp);

    SET_LOW_BITS_AREA_END(dest_buf,boundary_tmp);

  }

  return ((char *) boundary_tmp - (char *) dest_buf);
} 
