# @OSF_COPYRIGHT@
# 

# ppc.i - PowerPC instructions
#    ,
# By Eamonn McManus <emcmanus@gr.osf.org>, 1995.

# simplified mnemonics
# ori 0,0,0 
in 01100000000000000000000000000000 nop
# addi[s] rD,0,value
in 00111sddddd00000iiiiiiiiiiiiiiii li{|s}[$s] \
				    $reg($d),{$simm16($i)|$shifted16($i)}[$s]
# or rA,rS,rS
in 011111dddddaaaaabbbbb0110111100r {or{|.}[$r] $reg($a),$reg($b),$reg($d)|\
				     mr{|.}[$r] $reg($a),$reg($d)}[$b == $d]
in 011111dddddaaaaabbbbb0100111100r xor{|.}[$r] $reg($a),$reg($b),$reg($d)

# mtcrf 0xFF,rS
in 011111ddddd011111111000100100000 mtcr $reg($d)

in 00001Dcccccaaaaaiiiiiiiiiiiiiiii t{d|w}[$D]$tcond($c)i $reg($a),$simm16($i)
in 000111dddddaaaaaiiiiiiiiiiiiiiii mulli $reg($d),$reg($a),$simm16($i)
in 001000dddddaaaaaiiiiiiiiiiiiiiii subfic $reg($d),$reg($a),$simm16($i)
in 00101Uddd0laaaaaiiiiiiiiiiiiiiii cmp{l|}[$U]i \
				    $crcom($d){|1,}[$l]$reg($a),$simm16($i)
in 00110rdddddaaaaaiiiiiiiiiiiiiiii addic{|.}[$r] $reg($d),$reg0($a),$simm16($i)
in 00111sdddddaaaaaiiiiiiiiiiiiiiii addi{|s}[$s] $reg($d),$reg0($a),\
				    {$simm16($i)|$shifted16($i)}[$s]
in 010000cccccccccciiiiiiiiiiiiiial $br($c,$a,$l,,1)\
				    {$brdispl($i,14)|$brabs($i)}[$a]
in 01000100000000000000000000000010 sc
in 010010iiiiiiiiiiiiiiiiiiiiiiiial b{|l}[$l]{|a}[$a] \
				    {$brdispl($i,24)|$brabs($i)}[$a]
in 010011ddd00sss000000000000000000 mcrf $crf($d),$crf($s)
in 010011cccccccccc000000000010000l $br($c,0,$l,lr,0)
in 010011dddddaaaaabbbbb0oooo000010 cr$crop($o) $crb($d),$crb($a),$crb($b)
in 01001100000000000000000001100100 rfi
in 01001100000000000000000100101100 isync
in 010011cccccccccc000001000010000l $br($c,0,$l,ctr,0)
in 010111dddddaaaaabbbbbffffftttttr rlwnm{|.}[$r] \
				    $reg($a),$reg($d),$reg($b),$dec($f),$dec($t)
in 0101xxdddddaaaaasssssffffftttttr rl{wimi|winm|?|?}[$x]{|.}[$r] \
				    $reg($a),$reg($d),$dec($s),$dec($f),$dec($t)
in 011110dddddaaaaasssssffffff0xxSr rld{icl|icr|ic|imi}[$x]{|.}[$r] \
				    $reg($a),$reg($d),$dec($[sssssS]),$dec($f)
in 011110dddddaaaaabbbbbffffff100xr rldc{l|r}[$x]{|.}[$r] \
				    $reg($a),$reg($d),$reg($b),$dec($f)
in 011111ddd0laaaaabbbbb0000u000000 cmp{|l}[$u] \
				    $crcom($d){|1,}[$l]$reg($a),$reg($b)
in 011111cccccaaaaabbbbb000w0001000 t{w|d}[$w]$tcond($c) $reg($a),$reg($b)
in 011111dddddaaaaabbbbbo000C01000r subf{c|}[$C]{|o}[$o]{|.}[$r] \
				    $reg($d),$reg($a),$reg($b)
in 011111dddddaaaaabbbbb000u0010w1r mulh{d|w}[$w]{u|}[$u]{|.}[$r] \
				    $reg($d),$reg($a),$reg($b)
in 011111dddddaaaaabbbbbott0001010r add{c|e||?}[$t]{|o}[$o]{|.}[$r] \
				    $reg($d),$reg($a),$reg($b)
in 011111ddddd0000000000000m0100110 mf{cr|msr}[$m] $reg($d)
in 011111dddddaaaaabbbbb000w0101000 l{w|d}[$w]arx $reg($d),$reg0($a),$reg($b)
in 011111dddddaaaaabbbbb0000u101010 ld{|u}[$u]x $reg($d),$reg0($a),$reg($b)
in 011111dddddaaaaabbbbb0ooou101110 $ldst($o){|u}[$u]x \
				    $reg($d),$reg($a),$reg($b)
in 011111dddddaaaaabbbbb0000011A00r {slw|and}[$A]{|.}[$r] \
				    $reg($a),$reg($d),$reg($b)
in 011111dddddaaaaa000000000w11010r cntlz{w|d}[$w]{|.}[$r] $reg($a),$reg($d)
in 011111dddddaaaaabbbbb0000011011r sld{|.}[$r] $reg($a),$reg($d),$reg($b)
in 01111100000aaaaabbbbb00001101100 dcbst $reg($a),$reg($b)
in 011111dddddaaaaabbbbb0000111100r andc{|.}[$r] $reg($a),$reg($d),$reg($b)
in 01111100000aaaaabbbbb00010101100 dcbf $reg($a),$reg($b)
in 011111dddddaaaaa00000o001101000r neg{|o}[$o]{|.}[$r] $reg($d),$reg($a)
in 011111dddddaaaaabbbbb0001111100r nor{|.}[$r] $reg($a),$reg($d),$reg($b)
in 011111dddddaaaaabbbbbo01z001000r subf{|z}[$z]e{|o}[$o]{|.}[$r] \
				    $reg($d),$reg($a)
in 011111ddddd0ffffffff000100100m00 mt{crf $hex($f),|msr}[$m] $reg($d)
in 011111sssssaaaaabbbbb0010u101010 std{|u}[$u]x $reg($s),$reg0($a),$reg($b)
in 011111sssssaaaaabbbbb001w0101101 st{w|d}[$w]cx. $reg($s),$reg0($a),$reg($b)
in 011111dddddaaaaa00000o011001010r addze{|o}[$o]{|.}[$r] $reg($d),$reg($a)
in 011111sssss0rrrr0000000110100100 mtsr $dec($r),$reg($s)
in 011111dddddaaaaa00000o0111010x0r {subf|add}[$x]me{|o}[$o]{|.}[$r] \
				    $reg($d),$reg($a)
in 011111dddddaaaaabbbbbo0111010w1r mull{w|d}[$w]{|o}[$o]{|.}[$r] \
				    $reg($d),$reg($a),$reg($b)
in 011111sssss00000bbbbb00111100100 mtsrin $reg($s),$reg($b)
in 01111100000aaaaabbbbb00111101100 dcbtst $reg0($a),$reg($b)
in 01111100000aaaaabbbbb01000101100 dcbt $reg0($a),$reg($b)
in 011111sssssaaaaabbbbb0100011100r eqv{|.}[$r] $reg($a),$reg($s),$reg($b)
in 0111110000000000bbbbb01001100100 tlbie $reg($b)
in 011111dddddaaaaabbbbb01i01101100 ec{i|o}[$i]wx $reg($d),$reg0($a),$reg($b)
in 011111dddddrrrrrrrrrr01t10100110 m{f|t}[$t]spr $reg($d),$spr($r)
in 011111dddddaaaaabbbbb0101u101010 lwa{|u}[$u]x $reg($d),$reg($a),$reg($b)
in 01111100000000000000001011100100 tlbia
in 011111dddddtttttttttt01011100110 mftb $reg($d),$dec($t)
in 011111sssssaaaaabbbbb0110011100r orc{|.}[$r] $reg($a),$reg($s),$reg($b)
in 0111110000000000bbbbb01101100100 slbie $reg($b)
in 011111dddddaaaaabbbbbo111u010w1r div{d|w}[$w]{u|}[$u]{|o}[$o]{|.}[$r] \
				    $reg($d),$reg($a),$reg($b)
in 01111100000aaaaabbbbb01110101100 dcbi $reg0($a),$reg($b)
in 011111sssssaaaaabbbbb0111011100r nand{|.}[$r] $reg($a),$reg($s),$reg($b)
in 01111100000000000000001111100100 slbia
in 011111ddd00000000000010000000000 mcrxr $crf($d)
in 011111dddddaaaaabbbbb10000101010 lswx $reg($d),$reg0($a),$reg($b)
in 011111dddddaaaaabbbbb1w000101100 l{w|h}[$w]brx $reg($d),$reg0($a),$reg($b)
in 011111dddddaaaaabbbbb100su101110 lf{s|d}[$s]{|u}[$u]x \
				    $fr($d),$reg0($a),$reg($b)
in 011111sssssaaaaabbbbb1x000110w0r sr{|a}[$x]{w|d}[$w]{|.}[$r] \
				    $reg($a),$reg($s),$reg($b)
in 011111sssssaaaaabbbbb1000011011r srd{|.}[$r] $reg($a),$reg($s),$reg($b)
in 01111100000000000000010001101100 tlbsync
in 011111ddddd0rrrr0000010010101100 mfsr $reg($d),$dec($r)
in 011111dddddaaaaannnnn10010101010 lswi $reg($d),$reg0($a),$dec($n)
in 01111100000000000000010010101100 sync
in 011111ddddd00000bbbbb10100100110 mfsrin $reg($d),$reg($b)
in 011111sssssaaaaabbbbb10100101010 stswx $reg($s),$reg0($a),$reg($b)
in 011111sssssaaaaabbbbb1w100101100 st{w|h}[$w]brx $reg($s),$reg0($a),$reg($b)
in 011111sssssaaaaabbbbb101du101110 stf{s|d}[$d]{|u}[$u]x \
				    $fr($s),{$reg0($a)|$reg($a)}[$u],$reg($b)
in 011111sssssaaaaannnnn10110101010 stswi $reg($s),$reg0($a),$dec($n)
in 011111dddddaaaaasssss1100111000r srawi{|.}[$r] $reg($a),$reg($s),$dec($s)
in 01111100000000000000011010101100 eieio
in 011111sssssaaaaa00000111xx11010r exts{h|b|w|?}[$x]{|.}[$r] $reg($a),$reg($s)
in 01111100000aaaaabbbbb11110101100 icbi $reg0($a),$reg($b)
in 011111sssssaaaaabbbbb11110101110 stfiwx $fr($s),$reg0($a),$reg($b)
in 01111100000aaaaabbbbb11111101100 dcbz $reg0($a),$reg($b)
in 011Axsaaaaadddddiiiiiiiiiiiiiiii {{|x}[$x]or|{and|?}[$x]}[$A]i{|s}[$s]\
				    {|.}[$A] $reg($d),$reg($a),\
				    {$hex($i)|$shifted16($i)}[$s]
# Grouping andi with xori and ori may not be such a brilliant idea, since it
# gets invoked as a catch-all for the 011111 instructions below.  But that
# just means that we get a different sort of undefined instruction.
in 10111sdddddaaaaaiiiiiiiiiiiiiiii {l|st}[$s]mw \
				    $reg($d),$simm16($i)($reg0($a))
in 10oooudddddaaaaaiiiiiiiiiiiiiiii $ldst($o){|u}[$u] \
				    $reg($d),$simm16($i)($reg0($a))
in 110sDudddddaaaaaiiiiiiiiiiiiiiii {l|st}[$s]f{s|d}[$D]{|u}[$u] \
				    $fr($d),$simm16($i)($reg0($a))
in 111010dddddaaaaaiiiiiiiiiiiiiixy l{d{|u}[$y]|{|?}[$y]w}[$x] \
				    $reg($d),$simm16($i)($reg0($a))
in 111s11dddddaaaaabbbbb0000010010r fdiv{s|}[$s]{|.}[$r] \
				    $fr($d),$fr($a),$fr($b) 
in 111s11dddddaaaaabbbbb000001010xr f{sub|add}[$x]{s|}[$s]{|.}[$r] \
				    $fr($d),$fr($a),$fr($b) 
in 111s11ddddd00000bbbbb0000010110r fsqrt{s|}[$s]{|.}[$r] $fr($d),$fr($b)
in 111011ddddd00000bbbbb0000011000r fress{|.}[$r] $fr($d),$fr($b)
in 111s11dddddaaaaa00000ccccc11001r fmul{s|}[$s]{|.}[$r] \
				    $fr($d),$fr($a),$fr($c) 
in 111s11dddddaaaaabbbbbccccc111nxr f{|n}[$n]m{sub|add}[$x]{s|}[$s]{|.}[$r] \
				    $fr($d),$fr($a),$fr($c),$fr($b)
in 111110sssssaaaaaiiiiiiiiiiiiii0u std{|u}[$u] \
				    $reg($s),$simm16($i)({$reg0($a)|$reg($a)}[$u])
in 111111ccc00aaaaabbbbb0000o000000 fcmp{u|o}[$o] $crf($c),$fr($a),$fr($b)
in 111111ddddd00000bbbbb0000001100r frsp{|.}[$r] $fr($d),$fr($b)
in 111111ddddd00000bbbbb000000111zr fctiw{|z}[$z]{|.}[$r] $fr($d),$fr($b)
in 111111dddddaaaaabbbbbccccc10111r fsel{|.}[$r] \
				    $fr($d),$fr($a),$fr($c),$fr($b)
in 111111ddddd00000bbbbb0000011010r frsqrte{|,.}[$r] $fr($d),$fr($b)
in 111111ddddd0000000000000xx00110r mtfsb{?|1|0|?}[$x]{|.}[$r] $fcond($d)
in 111111ddddd00000bbbbb0000101000r fneg{|.}[$r] $fr($d),$fr($b)
in 111111ddd00sss000000000010000000 mcrfs $crf($d),$crf($s)
in 111111ddddd00000bbbbb0001001000r fmr{|.}[$r] $fr($d),$fr($b)
in 111111ddd0000000iiii00010000110r mtfsfi{|.}[$r] $crf($d),$simm16($i)
in 111111ddddd00000bbbbb0010001000r fnabs{|.}[$r] $fr($d),$fr($b)
in 111111ddddd00000bbbbb0100001000r fabs{|.}[$r] $fr($d),$fr($b)
in 111111ddddd00000000001001000111r mffs{|.}[$r] $fr($d)
in 1111110ffffffff0bbbbb1011000111r mtfsf{|.}[$r] $hex($f),$fr($b)
in 111111ddddd00000bbbbb110010111zr fctid{|z}[$z]{|.}[$r] $fr($d),$fr($b)
in 111111ddddd00000bbbbb1101001110r fcfid{|.}[$r] $fr($d),$fr($b)

in xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ?


ldst ooo {lwz|lbz|stw|stb|lhz|lha|sth|?}[$o]
br utdzyrrrcc(%a,%l,s,%C) b{d{nz|z}[$z]|{|?}[$z]}[$d]{c|}[$u]\
			  {|l}[$l]{|a}[$a]$s \
			  {$crcom($r)$cond($[cct]){|,}[$C]|}[$u]
cond ccc {ge|lt|le|gt|ne|eq|ns|so}[$c]
fcond ccc $hex($c)
crb rrrcc $cr($r):$cond($[cc1])
crop oooo {?|nor|?|?|andc|?|xor|nand|and|eqv|?|?|?|orc|or|?}[$o]
tcond ccccc {?|lgt|llt|?|eq|lge|lle|?|?|?|?|?|ge|?|?|?|lt|?|?|?|le|?|?|?|ne|?|?|?|?|?|?|a}[$c]

spr 0000000000 mq
spr 0000100000 xer
spr 0010l00000 rtc{u|l}[$l]
spr s011000000 dec{u|s}[$s]
spr 0100000000 lr
spr 0100100000 ctr
spr 1001000000 dsisr
spr 1001100000 dar
spr 1100100000 sdr1
spr 1101n00000 srr$dec($n)
spr 100nn01000 sprg$dec($n)
spr 1101001000 ear
spr 1101101000 pvr
spr 10nnl10000 ibat$dec($n){u|l}[$l]
spr 1000n11111 hid$dec($n)
spr 1001011111 iabr
spr 1010111111 dabr
spr 1111111111 pir
spr xxxxxxxxxx ?

reg0 00000 0
reg0 nnnnn $reg($n)

reg (%n) r$dec($n)
fr (%n) fr$dec($n)
cr (%n) cr$dec($n)
crf (%n) crf$dec($n)
crcom 000
crcom nnn $cr($n),

simm16 snnnnnnnnnnnnnnn {$hex($n)|-$hex((1 << 15) - $n)}[$s]

shifted16 (%n) $hex($n << 16)

brabs (%n) $hex($n << 2)

hex (%n) :
dec (%n) :
mbz (%n) :
brdispl (%d,%n) :
