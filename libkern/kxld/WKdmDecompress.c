#include <sys/cdefs.h>
#include "WKdm.h"

/***************************************************************************
 *          THE UNPACKING ROUTINES should GO HERE
 */

const char hashLookupTable [] = HASH_LOOKUP_TABLE_CONTENTS;

#if 0
#define GET_NEXT_TAG tags[tagsIndex++]
#define GET_NEXT_FULL_PATTERN fullPatterns[fullPatternsIndex++]
#define GET_NEXT_LOW_BITS lowBits[lowBitsIndex++]
#define GET_NEXT_DICTIONARY_INDEX dictionaryIndices[dictionaryIndicesIndex++]
#endif

/*  WK_unpack_2bits takes any number of words containing 16 two-bit values
 *  and unpacks them into four times as many words containg those
 *  two bit values as bytes (with the low two bits of each byte holding
 *  the actual value.
 */
static WK_word*
WK_unpack_2bits(WK_word *input_buf,
                WK_word *input_end,
                WK_word *output_buf) {

  register WK_word *input_next = input_buf;
  register WK_word *output_next = output_buf;
  register WK_word packing_mask = TWO_BITS_PACKING_MASK;

  /* loop to repeatedly grab one input word and unpack it into
   * 4 output words.  This loop could be unrolled a little---it's
   * designed to be easy to do that.
   */   
  while (input_next < input_end) {
    register WK_word temp = input_next[0];
    DEBUG_PRINT_2("Unpacked tags word: %.8x\n", temp);
    output_next[0] = temp & packing_mask;
    output_next[1] = (temp >> 2) & packing_mask;
    output_next[2] = (temp >> 4) & packing_mask;
    output_next[3] = (temp >> 6) & packing_mask;
    
    output_next += 4;
    input_next++;
  }

  return output_next;

}

/* unpack four bits consumes any number of words (between input_buf
 * and input_end) holding 8 4-bit values per word, and unpacks them
 * into twice as many words, with each value in a separate byte.
 * (The four-bit values occupy the low halves of the bytes in the
 * result).
 */
static WK_word*
WK_unpack_4bits(WK_word *input_buf,
                WK_word *input_end,
                WK_word *output_buf) {

  register WK_word *input_next = input_buf;
  register WK_word *output_next = output_buf;
  register WK_word packing_mask = FOUR_BITS_PACKING_MASK;
  
  
  /* loop to repeatedly grab one input word and unpack it into
   * 4 output words.  This loop should probably be unrolled
   * a little---it's designed to be easy to do that.
   */   
  while (input_next < input_end) {
    register WK_word temp = input_next[0];
    DEBUG_PRINT_2("Unpacked dictionary indices word: %.8x\n", temp);
    output_next[0] = temp & packing_mask;
    output_next[1] = (temp >> 4) & packing_mask;
    
    output_next += 2;
    input_next++;
  }
  
  return output_next;

}

/* unpack_3_tenbits unpacks three 10-bit items from (the low 30 bits of)
 * a 32-bit word
 */
static WK_word*
WK_unpack_3_tenbits(WK_word *input_buf,
                    WK_word *input_end,
                    WK_word *output_buf) {

  register WK_word *input_next = input_buf;
  register WK_word *output_next = output_buf;
  register WK_word packing_mask = LOW_BITS_MASK;
  
  /* loop to fetch words of input, splitting each into three
   * words of output with 10 meaningful low bits.  This loop
   * probably ought to be unrolled and maybe coiled
   */
  while (input_next < input_end) {
    register WK_word temp = input_next[0];
    
    output_next[0] = temp & packing_mask;
    output_next[1] = (temp >> 10) & packing_mask;
    output_next[2] = temp >> 20;
    
    input_next++;
    output_next += 3;
  }
  
  return output_next;

}

/*********************************************************************
 * WKdm_decompress --- THE DECOMPRESSOR                                 
 * Expects WORD pointers to the source and destination buffers
 * and a page size in words.  The page size had better be 1024 unless     
 * somebody finds the places that are dependent on the page size and 
 * fixes them
 */

void
WKdm_decompress (WK_word* src_buf,
		 WK_word* dest_buf,
		 __unused unsigned int words)
{

  DictionaryElement dictionary[DICTIONARY_SIZE];

  /* arrays that hold output data in intermediate form during modeling */
  /* and whose contents are packed into the actual output after modeling */

  /* sizes of these arrays should be increased if you want to compress
   * pages larger than 4KB
   */
  WK_word tempTagsArray[300];        /* tags for everything          */
  WK_word tempQPosArray[300];        /* queue positions for matches  */
  WK_word tempLowBitsArray[1200];    /* low bits for partial matches */

  PRELOAD_DICTIONARY;

#ifdef WK_DEBUG
  printf("\nIn DECOMPRESSOR\n");
  printf("tempTagsArray is at %p\n", tempTagsArray);
  printf("tempQPosArray is at %p\n", tempQPosArray);
  printf("tempLowBitsArray is at %p\n", tempLowBitsArray);

  printf(" first four words of source buffer are:\n");
  printf("   %u\n   %u\n   %u\n   %u\n",
         src_buf[0], src_buf[1], src_buf[2], src_buf[3]);
  
  { int i;
    WK_word *arr =(src_buf + TAGS_AREA_OFFSET + (PAGE_SIZE_IN_WORDS / 16));

    printf("  first 20 full patterns are: \n");
    for (i = 0; i < 20; i++) {
      printf(" %d", arr[i]);
    }
    printf("\n");
  }
#endif

  WK_unpack_2bits(TAGS_AREA_START(src_buf),
                  TAGS_AREA_END(src_buf),
                  tempTagsArray);

#ifdef WK_DEBUG
  { int i;
    char* arr = (char *) tempTagsArray;

    printf("  first 200 tags are: \n");
    for (i = 0; i < 200; i++) {
      printf(" %d", arr[i]);
    }
    printf("\n");
  }
#endif

  WK_unpack_4bits(QPOS_AREA_START(src_buf),
                  QPOS_AREA_END(src_buf),
                  tempQPosArray);

#ifdef WK_DEBUG
  { int i;
    char* arr = (char *) tempQPosArray;

    printf("  first 200 queue positions are: \n");
    for (i = 0; i < 200; i++) {
      printf(" %d", arr[i]);
    }
    printf("\n");
  }
#endif

  WK_unpack_3_tenbits(LOW_BITS_AREA_START(src_buf),
                      LOW_BITS_AREA_END(src_buf),
                      tempLowBitsArray);

#ifdef WK_DEBUG
  printf("AFTER UNPACKING, about to enter main block \n");
#endif

  {
    register char *next_tag = (char *) tempTagsArray;
    char *tags_area_end =
       ((char *) tempTagsArray) + PAGE_SIZE_IN_WORDS;
    char *next_q_pos = (char *) tempQPosArray;
    WK_word *next_low_bits = tempLowBitsArray;
    WK_word *next_full_word = FULL_WORD_AREA_START(src_buf);

    WK_word *next_output = dest_buf;

#ifdef WK_DEBUG
    printf("next_output is %u\n", next_output);

    printf("next_tag is %u \n", next_tag);
    printf("tags_area_end is %u\n", tags_area_end);
    printf("next_q_pos is %u\n", next_q_pos);
    printf("next_low_bits is %u\n", next_low_bits);
    printf("next_full_word is %u\n", next_full_word);
#endif 

    /* this loop should probably be unrolled. Maybe we should unpack
     * as 4 bit values, giving two consecutive tags, and switch on
     * that 16 ways to decompress 2 words at a whack
     */
    while (next_tag < tags_area_end) {

       char tag = next_tag[0];

       switch(tag) {

         case ZERO_TAG: {
            *next_output = 0;
            break;
         }
         case EXACT_TAG: {
            WK_word *dict_location = dictionary + *(next_q_pos++);
            /* no need to replace dict. entry if matched exactly */
            *next_output = *dict_location;
            break;
         }
         case PARTIAL_TAG: {
            WK_word *dict_location = dictionary + *(next_q_pos++);
            {
               WK_word temp = *dict_location;

               /* strip out low bits */
               temp = ((temp >> NUM_LOW_BITS) << NUM_LOW_BITS);

               /* add in stored low bits from temp array */
               temp = temp | *(next_low_bits++);

               *dict_location = temp;      /* replace old value in dict. */
               *next_output = temp;    /* and echo it to output */
            }
            break;
         }
         case MISS_TAG: {
            WK_word missed_word = *(next_full_word++);
            WK_word *dict_location = 
              (WK_word *)
              ((void *) (((char *) dictionary) + HASH_TO_DICT_BYTE_OFFSET(missed_word)));
            *dict_location = missed_word;
            *next_output = missed_word;
            break;
         }
       }
       next_tag++;
       next_output++;
    }

#ifdef WK_DEBUG        
    printf("AFTER DECOMPRESSING\n");
    printf("next_output is %p\n", next_output);
    printf("next_tag is %p\n", next_tag);
    printf("next_full_word is %p\n", next_full_word);
    printf("next_q_pos is %p\n", next_q_pos);
#endif
  }
}
