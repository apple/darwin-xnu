from xnu import *
from utils import *


@lldb_type_summary(['bank_element', 'bank_element_t'])
@header("{0: <20s} {1: <16s} {2: <16s} {3: <16s} {4: <20s} {5: <20s}".format("bank_element", "type", "ref_count", "sync", "task", "process_name"))
def GetBankElementSummary(bank_element):
    """ Summarizes the bank element
        params: bank_element = value of the object of type bank_element_t
        returns: String with summary of the type.
    """
    format_str = "{0: <#020x} {1: <16s} {2: <16d} {3: <16d}"

    if bank_element.be_type == 0:
      out_string = format_str.format(bank_element, "BANK_TASK", unsigned(bank_element.be_refs), unsigned(bank_element.be_made))
    else:
      out_string = format_str.format(bank_element, "BANK_ACCOUNT", unsigned(bank_element.be_refs), unsigned(bank_element.be_made))

    #if DEVELOPMENT
    format_str = "{0: <#020x} {1: <20s}"
    if hasattr(bank_element, 'be_task'):
      out_string += " " + format_str.format(bank_element.be_task, GetProcNameForTask(bank_element.be_task))
    #endif

    return out_string


@lldb_type_summary(['bank_task', 'bank_task_t'])
@header("{0: <20s} {1: <16s} {2: <20s} {3: <16s} {4: <16s} {5: <16s} {6: <16s} {7: <16s} {8: <20s} {9: <20s}".format("bank_task", "pid", "ledger", "ref_count", "sync", "persona id", "uid", "gid", "task", "process_name"))
def GetBankTaskSummary(bank_task):
    """ Summarizes the bank task
        params: bank_task = value of the object of type bank_task_t
        returns: String with summary of the type.
    """

    format_str = "{0: <#020x} {1: <16d} {2: <#020x} {3: <16d} {4: <16d} {5: <16d} {6: <16d} {7: <16d}"
    out_string = format_str.format(bank_task, bank_task.bt_proc_persona.pid, bank_task.bt_ledger, unsigned(bank_task.bt_elem.be_refs), unsigned(bank_task.bt_elem.be_made), bank_task.bt_proc_persona.persona_id, bank_task.bt_proc_persona.uid, bank_task.bt_proc_persona.gid)

    #if DEVELOPMENT
    format_str = "{0: <#020x} {1: <20s}"
    if hasattr(bank_task.bt_elem, 'be_task'):
      out_string += " " + format_str.format(bank_task.bt_elem.be_task, GetProcNameForTask(bank_task.bt_elem.be_task))
    #endif
    return out_string


@lldb_type_summary(['bank_account', 'bank_account_t'])
@header("{0: <20s} {1: <16s} {2: <16s} {3: <16s} {4: <16s} {5: <20s} {6: <16s} {7: <16s} {8: <20s} {9: <20s} {10: <20s} {11: <20s}".format("bank_account", "holder_pid", "merchant_pid", "secure_orig", "proximal_pid", "chit_ledger", "ref_count", "sync", "holder_task", "holder_process", "merchant_task", "merchant_process"))
def GetBankAccountSummary(bank_account):
    """ Summarizes the bank account
        params: bank_task = value of the object of type bank_account_t
        returns: String with summary of the type.
    """

    format_str = "{0: <#020x} {1: <16d} {2: <16d} {3: <16d} {4: <16d} {5: <#020x} {6: <16d} {7: <16d}"
    out_string = format_str.format(bank_account, bank_account.ba_holder.bt_proc_persona.pid, bank_account.ba_merchant.bt_proc_persona.pid, bank_account.ba_secureoriginator.bt_proc_persona.pid, bank_account.ba_proximateprocess.bt_proc_persona.pid,bank_account.ba_bill, unsigned(bank_account.ba_elem.be_refs), unsigned(bank_account.ba_elem.be_made))

    #if DEVELOPMENT
    format_str = "{0: <#020x} {1: <20s}"
    if hasattr(bank_account.ba_holder.bt_elem, 'be_task'):
      out_string += " " + format_str.format(bank_account.ba_holder.bt_elem.be_task, GetProcNameForTask(bank_account.ba_holder.bt_elem.be_task))
    if hasattr(bank_account.ba_merchant.bt_elem, 'be_task'):
      out_string += " " + format_str.format(bank_account.ba_merchant.bt_elem.be_task, GetProcNameForTask(bank_account.ba_merchant.bt_elem.be_task))
    #endif
    return out_string


# Macro: showbankaccountstopay
@lldb_command('showbankaccountstopay')
def ShowBankAccountsToPay(cmd_args=None, cmd_options={}):
    """ show a list of merchant bank tasks for a bank_task object.
        Usage: (lldb)showbankaccountstopay <bank_task_t>
    """
    if not cmd_args:
      raise ArgumentError("Please provide arguments")

    bank_task = kern.GetValueFromAddress(cmd_args[0], 'bank_task_t')
    print GetBankTaskSummary.header
    print GetBankTaskSummary(bank_task)
    print "List of Accounts to Pay."
    header_str = GetBankAccountSummary.header
    print header_str

    for bank_account in IterateQueue(bank_task.bt_accounts_to_pay, 'bank_account_t', 'ba_next_acc_to_pay'):
      print GetBankAccountSummary(bank_account)
    return
# EndMacro: showbankaccountstopay


# Macro: showbankaccountstocharge
@lldb_command('showbankaccountstocharge')
def ShowBankAccountsToCharge(cmd_args=None, cmd_options={}):
    """ show a list of holder bank tasks for a bank_task object.
        Usage: (lldb)showbankaccountstocharge <bank_task_t>
    """
    if not cmd_args:
      raise ArgumentError("Please provide arguments")

    bank_task = kern.GetValueFromAddress(cmd_args[0], 'bank_task_t')
    print GetBankTaskSummary.header
    print GetBankTaskSummary(bank_task)
    print "List of Accounts to Charge."
    header_str = GetBankAccountSummary.header
    print header_str

    for bank_account in IterateQueue(bank_task.bt_accounts_to_charge, 'bank_account_t', 'ba_next_acc_to_charge'):
      print GetBankAccountSummary(bank_account)
    return
# EndMacro: showbankaccountstocharge


#if DEVELOPMENT

# Macro: showallbanktasklist
@lldb_command('showallbanktasklist')
def ShowAllBankTaskList(cmd_args=None, cmd_options={}):
    """ A DEVELOPMENT macro that walks the list of all allocated bank_task objects
        and prints them.
        usage: (lldb) showallbanktasklist
    """
    if not hasattr(kern.globals, 'bank_tasks_list'):
      print "It seems you are running a build of kernel that does not have the list of all bank_tasks_list."
      return False
    print GetBankTaskSummary.header
    for bank_task in IterateQueue(kern.globals.bank_tasks_list, 'bank_task_t', 'bt_global_elt'):
      print GetBankTaskSummary(bank_task)
    return True
# EndMacro showallbanktasklist


# Macro: showallbankaccountlist
@lldb_command('showallbankaccountlist')
def ShowAllBankAccountList(cmd_args=None, cmd_options={}):
    """ A DEVELOPMENT macro that walks the list of all allocated bank_account objects
        and prints them.
        usage: (lldb) showallbankaccountlist
    """
    if not hasattr(kern.globals, 'bank_accounts_list'):
      print "It seems you are running a build of kernel that does not have the list of all bank_accounts_list."
      return False
    print GetBankAccountSummary.header
    for bank_account in IterateQueue(kern.globals.bank_accounts_list, 'bank_account_t', 'ba_global_elt'):
      print GetBankAccountSummary(bank_account)
    return True
# EndMacro showallbankaccountlist
#endif
