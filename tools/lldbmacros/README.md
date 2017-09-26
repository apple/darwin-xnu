Table of Contents
=================

      A. How to use lldb for kernel debugging
      B. Design of lldb kernel debugging platform.
      C. Kernel debugging commands.
          i. Using commands.
         ii. Writing new commands.
      D. Kernel type summaries.
          i. Using summaries
         ii. Writing new summary functions
      E. FAQ and General Coding Guidelines
          i. Frequently Asked Questions
         ii. Formatted Output printing guidelines [MUST READ]
        iii. Coding conventions.  [MUST READ]
         iv. Submitting changes in lldbmacros [MUST READ]
          v. Common utility functions and paradigms
      F. Development and Debugging on lldb kernel debugging platform.
          i. Reading a exception backtrace
         ii. Loading custom or local lldbmacros and operating_system plugin
        iii. Adding debug related 'printf's

A. How to use lldb for kernel debugging
========================================

lldb can be used for kernel debugging the same way as gdb. The simplest way is to start lldb with kernel symbol file. The lldb environment by default does not allow loading automatic python modules. Please add the following setting in

    File: ~/.lldbinit
    settings set target.load-script-from-symbol-file true

Now lldb will be ready to connect over kdp-remote '\<hostname:port>' or 'gdb-remote \<hostname:port>'. In case using a core file please do 'file --core /path/to/corefile'

Following are detailed steps on how to debug a panic'ed / NMI'ed machine (For the curious souls).

lldb debugging in detail:-

  * start lldb with the right symbols file. If you do not know the version apriori, then enable dsymForUUID to load symbols dynamically.
        bash$ dsymForUUID --enable
        bash$ lldb /path/to/mach_kernel.symbols
        Current executable set to '/Sources/Symbols/xnu/xnu-2253~2/mach_kernel' (x86_64).
        (lldb)

  * connect to remote device or load a core file
        #for kdp
        (lldb) process connect --plugin kdp-remote udp://17.123.45.67:41139
        #for gdb (eg with astris)
        (lldb) process connect --plugin gdb-remote gdb://17.123.45.67:8000
        #for loading a core file
        (lldb) file --core /path/to/core/file  /path/to/kernel_symbol_file

  * Once connected you can debug with basic lldb commands like print, bt, expr etc. The xnu debug macros will also be loaded automatically from the dSYM files.
  In case if you are working with older kernel files you can load kernel specific commands by doing -
        (lldb) command script import /path/to/xnu/tools/lldbmacros/xnu.py
        (lldb) showbootargs
        debug=0x14e ncpus=2

  * You can do `kgmhelp` to get a list of commands available through xnu.py

SPECIAL: The `xnu.py` script brings in kernel type summary functions. To enable these please do -

    (lldb) showlldbtypesummaries

These could be very handy in printing important information from structures easily.
For ex.

    (lldb) print (thread_t)0x80d6a620
    (thread_t) $45 = 0x80d6a620
    thread                   thread_id  processor            pri    io_policy  state wait_queue           wait_event           wmesg                thread_name
    0x80d6a620               0x317      0x902078c8           61                W     0x910cadd4           0x0                                       SystemSoundServer



B. Design of lldb kernel debugging platform.
=============================================

The lldb debugger provides python scripting bridge for customizing commands and summaries in lldb. Following is the stack of platforms and how commands and summaries interact with it.

    |------- xnu scripts ----------|
    | |- lldb Command/Scripting-|  |   <-- provides scriptability for kernel data structures through summary/command invocation.
    | |    |--lldb core--|      |  |   <-- interacts with remote kernel or corefile.
    | |-------------------------|  |
    |------------------------------|

The xnu script in xnu/tools/lldbmacros provides the following:

  * Custom functions to do plumbing of lldb command invocation to python function call. (see doc strings for @lldb_command)
    The command interface provides some common features (which can be invoked after passing '--' on cmd line) like -

      i. send the output of command to file on disk
      ii. search for a string in the output and selectively print the line containing it.
      iii. -v options to increase verbosity levels in commands.
        For example: (lldb)showalltasks -- -s kernel_task --o /tmp/kernel_task.output -v
        will show task summary output with lines matching string 'kernel_task' into a file /tmp/kernel_task.output and with a verbosity level of (default +1)

  * Customization for plugging in summary functions for lldb type summaries. (see doc strings for @lldb_summary)
     It will automatically register given types with the functions within the kernel category.

  * Ability to register test cases for macros (see doc strings for @xnudebug_test).

The file layout is like following

    xnu/
     |-tools/
       |-lldbmacros/
         |-core/       # Core logic about kernel, lldb value abstraction, configs etc. **DO NOT TOUCH THIS DIR**
         |-plugins/    # Holds plugins for kernel commands.
         |-xnu.py      # xnu debug framework along with kgmhelp, xnudebug commands.
         |-xnudefines.py
         |-utils.py
         |-process.py  # files containing commands/summaries code for each subsystem
         |-...


The lldbmacros directory has a Makefile that follows the build process for xnu. This packages lldbmacros scripts into the dSYM of each kernel build. This helps in rev-locking the lldb commands with changes in kernel sources.


C. Kernel debugging commands.
==============================
i. Using commands.
------------------
Using xnu debug commands is very similar to kgmacros in gdb. You can use 'kgmhelp' to get a listing of available commands.
If you need detailed help for a command please type 'help <command name>' and the documentation for the command will be displayed.
For ex.

    (lldb) help pmap_walk
    Perform a page-table walk in <pmap> for <virtual_address>.
         You can pass -- -v for verbose output. To increase the verbosity add more -v args after the '--'.
    Syntax: pmap_walk <pmap> <virtual_address>

The basic format for every command provided under kgmhelp is like follows

    (lldb) command_name [cmd_args..] [-CMDOPTIONS] [-xnuoptions]
    where:
      command_name : name of command as registed using the @lldb_command decorator and described in 'kgmhelp'
      cmd_args     : shell like arguments that are passed as is to the registered python function.
                     If there is error in these arguments than the implementor may display according error message.
      xnuoptions   : common options for stream based operations on the output of command_name.
                     Allowed options are
                     -h          : show help string of a command
                     -s <regexp> : print only the lines matching <regexp>
                     -o <file>   : direct the output of command to <file>. Will not display anything on terminal
                     -v          : increase the verbosity of the command. Each '-v' encountered will increase verbosity by 1.
                     -p <plugin> : pass the output of command to <plugin> for processing and followup with command requests by it.
      CMDOPTIONS   : These are command level options (always a CAPITAL letter option) that are defined by the macro developer. Please do
                     help <cmdname> to know how each option operates on that particular command. For an example of how to use CMDOPTIONS, take a look at vm_object_walk_pages in memory.py

ii. Writing new commands.
--------------------------
The python modules are designed in such a way that the command from lldb invokes a python function with the arguments passed at lldb prompt.

It is recommended that you do a decoupled development for command interface and core utility function so that any function/code can be called as a simple util function and get the same output. i.e.

    (lldb)showtask 0xabcdef000 is same as python >>> GetTaskSummary(0xabcdef000) or equivalent

Following is a step by step guideline on how to add a new command ( e.g showtaskvme ). [extra tip: Always good idea to wrap your macro code within # Macro: , # EndMacro.]

  1. register a command to a function. Use the lldb_command decorator to map a 'command_name' to a function. Optionally you can provide getopt compatible option string for customizing your command invocation. Note: Only CAPITAL letter options are allowed. lowercase options are reserved for the framework level features.

  2. Immediately after the register define the function to handle the command invocation. The signature is always like Abc(cmd_args=None, cmd_options={})

  3. Add documentation for Abc(). This is very important for lldb to show help for each command. [ Follow the guidelines above with documentation ]

  4. Use cmd_args array to get args passed on command. For example a command like `showtaskvme 0xabcdef00` will put have cmd_args=['0xabcdef00']
      - note that we use core.value class as an interface to underlying C structures. Refer [Section B] for more details.
      - use kern.globals.\<variable_name> & kern.GetValueFromAddress for building values from addresses.
      - remember that the ideal type of object to be passed around is core.value
      - Anything you 'print' will be relayed to lldb terminal output.

  5. If the user has passed any custom options they would be in cmd_options dict. the format is `{'-<optionflag>':'<value>'}`. The \<value> will be '' (empty string) for non-option flags.

  6. If your function finds issue with the passed argument then you can `raise ArgumentError('error_message')` to notify the user. The framework will automatically catch this and show appropriate help using the function doc string.

  7. Please use "##" for commenting your code. This is important because single "#" based strings may be mistakenly considered in `unifdef` program.

 Time for some code example? Try reading the code for function ShowTaskVmeHelper in memory.py.

SPECIAL Note: Very often you will find yourself making changes to a file for some command/summary and would like to test it out in lldb.

To easily reload your changes in lldb please follow the below example.

  * you fire up lldb and start using zprint. And soon you need to add functionality to zprint.

  * you happily change a function code in memory.py file to zprint macro.

  * now to reload that particular changes without killing your debug session do
        (lldb) xnudebug reload memory
         memory is reloaded from ./memory.py
        (lldb)

  * Alternatively, you can use lldb`s command for script loading as
        (lldb) command script import /path/to/memory.py
    You can re-run the same command every time you update the code in file.

 It is very important that you do reload using xnudebug command as it does the plumbing of commands and types for your change in the module. Otherwise you could easily get confused
 why your changes are not reflected in the command.


D. Kernel type summaries.
==========================
i. Using summaries
------------------
The lldb debugger provides ways for user to customize how a particular type of object be decsribed when printed. These are very useful in displaying complex and large structures
where only certain fields are important based on some flag or value in some field or variable. The way it works is every time lldb wants to print an object it checks
for registered summaries. We can define python functions and hook it up with lldb as callbacks for type summaries.  For example.

    (lldb) print first_zone
    (zone_t) $49 = 0xd007c000
          ZONE            TOT_SZ ALLOC_ELTS  FREE_ELTS    FREE_SZ ELT_SZ  ALLOC(ELTS  PGS  SLK)     FLAGS      NAME
    0x00000000d007c000      29808        182         25       3600    144   4096   28    1   64   X$          zones
    (lldb)
Just printing the value of first_zone as (zone_t) 0xd007c000 wouldnt have been much help. But with the registered summary for zone_t we can see all the interesting info easily.

You do not need to do anything special to use summaries. Once they are registered with lldb they show info automatically when printing objects. However if you wish to
see all the registered type summaries run the command `type summary list -w kernel` on lldb prompt.
Also if you wish to quickly disable the summaries for a particular command use the `showraw` command.

ii. Writing new summary functions
---------------------------------
lldb provides really flexible interface for building summaries for complex objects and data. If you find that a struct or list can be
diagnosed better if displayed differently, then feel free to add a type summary for that type. Following is an easy guide on how to do that.

  1. Register a function as a callback for displaying information for a type. Use the `@lldb_type_summary()` decorator with an array of types you wish to register for callback

  2. Provide a header for the summary using `@header()` decorator. This is a strong requirement for summaries. This gets displayed before the output
     of `GetTypeSummary()` is displayed. [In case you do not wish to have header then still define it as "" (empty string) ]

  3. Define the function with signature of `GetSomeTypeSummary(valobj)`. It is highly recommended that the naming be consistent to `Get.*?Summary(valobj)`
     The valobj argument holds the core.value object for display.

  4. Use the utility functions and memory read operations to pull out the required information.
     [ use `kern.globals` & `kern.GetValueFromAddress` for building args to core functions. ]
     [ remember that the ideal type of object to be passed around is core.value ]

  5. return a string that would be printed by the caller. When lldb makes a call back it expects a str to be returned. So do not print
     directly out to console. [ debug info or logs output is okay to be printed anywhere :) ]

Time for some code example? Try reading the code for GetTaskSummary() in process.py.



E. FAQs and Generel Coding Guidelines
======================================

i. Frequently Asked Questions
-----------------------------

  Q. How do I avoid printing the summary and see the actual data in a structure?

  A. There is a command called `showraw`. This will disable all kernel specific type summaries and execute any command you provide. For ex.

    (lldb) print (thread_t) 0x80d6a620
    (thread_t) $45 = 0x80d6a620
    thread                   thread_id  processor            pri    io_policy  state wait_queue           wait_event           wmesg                thread_name
    0x80d6a620               0x317      0x902078c8           61                W     0x910cadd4           0x0                                       SystemSoundServer
    (lldb) showraw print (thread_t) 0x80d6a620
    (thread_t) $48 = 0x80d6a620

  Q. I typed `showallvnodes` and nothing happens for a long time? OR How do I get output of long running command instantly on the terminal?

  A. The lldb command interface tries to build result object from output of a python function. So in case of functions with very long output or runtime it may
     seem that the lldb process is hung. But it is not. You can use "-i" option to get immediate output on terminal.

        ex. (lldb) showallvnodes -- -i
         Immediate Output
         ....

  Q. I made a change in a python file for a command or summary, but the output is not reflected in the lldb command?

  A. The python framework does not allow for removing a loaded module and then reloading it. So sometimes if a command has a cached value from
     old code that it will still call the old function and hence will not display new changes in file on disk. If you find yourself in such a situation
     please see [Section C. -> SPECIAL Note]. If the change is to basic class or caching mechanism than it is advised to quit lldb and re-load all modules again.

  Q. I am new to python. I get an error message that I do not understand. what should I do?

  A. The syntax for python is different from conventional programming languages. If you get any message with SyntaxError or TypeError or ValueError then please review your code and look for common errors like

  - wrong level of indentation?
  - missed a ':' at the end of an if, elif, for, while statement?
  - referencing a key in dictionary that doesn't exist? You might see KeyError in such cases.
  - mistakenly used python reserved keyword as variable? (check http://docs.python.org/release/3.0.1/reference/lexical_analysis.html#id8)
  - Trying to modify a string value? You can only create new strings but never modify existing ones.
  - Trying to add a non string value to a string? This typically happens in print "time is " + gettime(). here gettime() returns int and not str.
  - using a local variable with same name as global variable?
  - assigning a value to global variable without declaring first? Its highly recommended to always declare global variable with 'global' keyword
  If you still have difficulty you can look at the python documentation at http://docs.python.org


  Q. I wish to pass value of variable/expression to xnu lldb macro that accepts only pointers. How can I achieve that?

  A. Many lldb macros have syntax that accepts pointers (eg showtaskstacks etc). In order to have your expression be evaluated before passing to command use `back ticks`. For example:

        (lldb) showtaskstacks  `(task_t)tasks.next`
        This way the expressing withing ` ` is evaluated by lldb and the value is passed to the command.
        Note that if your argument pointer is bad or the memory is corrupted lldb macros will fail with a long backtrace that may not make sense. gdb used to fail silently but lldb does not.
        Please see Section F(i) for more information on reading backtraces.

  Q. I connected to a coredump file with lldb --core corefile and I got RuntimeError: Unable to find lldb thread for tid=XYZ. What should I do?

  A. This is most likely the case that lldb ignored the operating system plugin in the dSYM and hence threads are not populated. Please put the line 'settings set target.load-script-from-symbol-file true' in your ~/.lldbinit file. If you do not have access you can alternatively do

        bash# lldb
        (lldb) settings set target.load-script-from-symbol-file true
        (lldb) file --core corefile


ii. Formatted output printing - zen and peace for life
------------------------------------------------------

To avoid the horrors of printing a tabular data on console and then 2 weeks later again messing with it for a new field, it is recommended to follow these guidelines.

  * any python string can be invoked to "".format() and hence makes it very easy to play with formats

  * As a convention, I suggest that for printing pointer values in hex use "{0: <#020x}".format(some_int_value). This will print nice 0x prefixed strings with length padded to 20.

  * If you need help with format options take a look at http://docs.python.org/library/string.html#format-string-syntax

  * [ I'd first create a format string for data and then for the header just change the x's and d's to s and pass the header strings to format command. see GetTaskSummary()]

  * If you need to print a string from a core.value object then use str() to get string representation of value.


iii. Coding conventions
-----------------------
It is very very HIGHLY RECOMMENDED to follow these guidelines for writing any python code.

 * Python is very sensitive to tabs and spaces for alignment. So please make sure you **INDENT YOUR CODE WITH SPACES** at all times.

 * The standard tab width is 4 spaces. Each increasing indent adds 4 spaces beginning of the line.

 * The format for documentation is -
        """ A one line summary describing what this function / class does
            Detailed explanation if necessary along with params and return values.
        """

 * All Classes and functions should have a doc string describing what the function does
   A consistent format is expected. For ex.
    def SumOfNumbers(a, b, c, d):
        """ Calculate sum of numbers.
            params:
                a - int, value to be added. can be 0
                b - int/float, value to be added.
            returns:
                int/float - Sum of two values
            raises:
                TypeError - If any type is not identified in the params
        """

 * A Class or Function should always start with CAPITAL letter and be CamelCase. If a function is for internal use only than it starts with '_'.

 * Function params should always be lower_case and be word separated with '_'

 * A local variable inside a function should be lower_case and separated with '_'

 * A variable for internal use in object should start with '_'.

 * if a class variable is supposed to hold non native type of object, it is good idea to comment what type it holds

 * A class function with name matching `Get(.*?)Summary()` is always supposed to return a string which can be printed on stdout or any file.

 * Functions beginning with "Get" (eg. GetVnodePath())  mean they return a value and will not print any output to stdout.

 * Functions beginning with "Show"  (eg. ShowZTrace()) mean they will print data on screen and may not return any value.


iv. Submitting changes in lldbmacros
------------------------------------

To contribute new commands or fixes to existing one, it is recommended that you follow the procedure below.

  * Save the changes requried for new command or fix into lldbmacros directory.

  * Make sure that the coding conventions are strictly followed.

  * Run syntax checker on each of the modified files. It will find basic formatting errors in the changed files for you.

  * If you are adding new file then please update the Makefile and xnu.py imports to ensure they get compiled during kernel build.

  * Do a clean build of kernel from xnu top level directory.

  * Verify that your changes are present in the dSYM directory of new build.

  * Re-run all your test and verification steps with the lldbmacros from the newly packaged dSYM/Contents/Resources/Python/lldbmacros.

v. Common utility functions and paradigms
-----------------------------------------
Please search and look around the code for common util functions and paradigm

  * Take a peek at utils.py for common utility like sizeof_fmt() to humanize size strings in KB, MB etc. The convention is to have functions that do self contained actions and does not require intricate knowledge of kernel structures in utils.py

  * If you need to get pagesize of the traget system, do not hard code any value. kern.globals.page_size is your friend. Similarly use config['verbosity'] for finding about configs.

  * If you are developing a command for structure that is different based on development/release kernels please use "hasattr()" functionality to conditionalize referencing #ifdef'ed fields in structure. See example in def GetTaskSummary(task) in process.py


F. Development and Debugging on lldb kernel debugging platform.
===============================================================

i. Reading a exception backtrace
--------------------------------
In case of an error the lldbmacros may print out an exception backtrace and halt immediately. The backtrace is very verbose and may be confusing. The important thing is to isolate possible causes of failure, and eventually filing a bug with kernel team. Following are some common ways where you may see an exception instead of your expected result.

  * The lldbmacros cannot divine the type of memory by inspection. If a wrong pointer is passed from commandline then, the command code will try to read and show some results. It may still be junk or plain erronous. Please make sure your command arguments are correct.
    For example: a common mistake is to pass task address to showactstack. In such a case lldb command may fail and show you a confusing backtrace.

 * Kernel debugging is particularly tricky. Many parts of memory may not be readable. There could be failure in network, debugging protocol or just plain bad memory. In such a case please try to see if you can examine memory for the object you are trying to access.

 * In case of memory corruption, the lldbmacros may have followed wrong pointer dereferencing. This might lead to failure and a exception to be thrown.


ii. Loading custom or local lldbmacros and operating_system plugin
------------------------------------------------------------------

The lldbmacros are packaged right into the dSYM for the kernel executable. This makes debugging very easy since they can get loaded automatically when symbols are loaded.
However, this setup makes it difficult for a lldbmacro developer to load custom/local macros. Following is the suggested solution for customizing your debugging setup:

  * set up environment variable DEBUG_XNU_LLDBMACROS=1 on your shell. This will disable the automatic setup of lldbmacros and the operating_system.py from the symbols.
     - bash$ export DEBUG_XNU_LLDBMACROS=1

  * start lldb from the shell
     - bash$ lldb

  * [optional] If you are making changes in the operating_system plugin then you need to set the plugin path for lldb to find your custom operating_system plugin file.
     - (lldb)settings set target.process.python-os-plugin-path /path/to/xnu/tools/lldbmacros/core/operating_system.py
     If you do not wish to change anything in operating_system plugin then just leave the setting empty. The symbol loading module will set one up for you.

  * Load the xnu debug macros from your custom location.
     - (lldb)command script import /path/to/xnu/tools/lldbmacros/xnu.py


iii. Adding debug related 'printf's
-----------------------------------

The xnu debug framework provides a utility function (debuglog) in utils.py. Please use this for any of your debugging needs. It will not print any output unless the user turns on debug logging on the command. Please check the documentaiton of debuglog for usage and options.

  * To enable/disable logging
     - (lldb) xnudebug debug
       Enabled debug logging.


