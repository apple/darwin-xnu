#!/bin/bash
# persona_test_run.sh
#
# This file aims to be a comprehensive test suite for the persona subsystem.
# It uses two tools:
#   1. persona_mgr - create, destroy, lookup personas
#   2. persona_spawn - spawn processes into personas with a variety of options
# The script relies heavily on the particular output of these tools, so if you
# are modifying / extending those tools, this file also need to be updated to
# properly capture the new output. Specifically, the get_persona_info function
# needs to be maintained / updated.
#
# NOTE: the function get_persona_info() also needs to be kept up to date with
# the types of personas found in bsd/sys/persona.h

# be sure to bail on script errors and unepected tool failures
set -e

PERSONA_MGR="${PWD}/persona_mgr"
PERSONA_SPAWN="${PWD}/persona_spawn"

if [ ! -d "$TMPDIR" ]; then
	echo "Couldn't find temp directory '$TMPDIR': check permissions/environment?"
	exit 255
fi

if [ ! -e "${PERSONA_MGR}" ] ||  [ ! -x "${PERSONA_MGR}" ]; then
	echo "Can't find '${PERSONA_MGR}': skipping test"
	exit 0
fi
if [ ! -e "${PERSONA_SPAWN}" ] || [ ! -x "${PERSONA_SPAWN}" ]; then
	echo "Can't find '${PERSONA_SPAWN}': skipping test"
	exit 0
fi

function check_for_persona_support() {
	local errno=0
	${PERSONA_MGR} support || errno=$?
	if [ $errno -eq 78 ]; then
		echo "Persona subsystem is not supported - skipping tests"
		exit 0
	fi
	return 0
}
check_for_persona_support


## bail [failure_msg]
#
# exit the script with an error code that corresponds to the line number
# from which this function was invoked. Because we want to exit with a
# non-zero exit code, we use: 1 + (254 % line).
#
function bail() {
	local msg="$1"
	local line=$2
	if [ -z "$line" ]; then
		line=${BASH_LINENO[0]}
	fi
	echo "[$line] ERROR: $msg" 1>&2
	exit $((1 + $line % 254))
}

## check_return [message_on_failure]
#
# Check the return value of the previous command or script line. If the
# value of '$?' is not 0, then call bail() with an appropriate message.
#
function check_return() {
	local err=$?
	local msg=$1
	local line=$2
	if [ -z "$line" ]; then
		line=${BASH_LINENO[0]}
	fi
	echo "CHECK: $msg"
	if [ $err -ne 0 ]; then
		bail "e=$err: $msg" $line
	fi

	return 0
}

## expect_failure [message_on_success]
#
# Check the return value of the previous command or script line. If the
# value of '$?' is 0 (success), then call bail() with a message saying
# that we expected this previous command/line to fail.
# 
function expect_failure() {
	local err=$?
	local msg=$1
	local line=$2
	if [ -z "$line" ]; then
		line=${BASH_LINENO[0]}
	fi
	if [ $err -eq 0 ]; then
		bail "found success, expected failure: $msg" $line
	fi

	echo "EXPECT: failure: $msg"
	return 0
}

## test_num [debug_info] [number]
#
# Check that a variable value is a number, bail() on error.
#
function test_num() {
	local type=$1
	local num=$2
	local line=$3
	if [ -z "$line" ]; then
		line=${BASH_LINENO[0]}
	fi
	if [ -z "$num" ]; then
		bail "invalid (NULL) $type" $line
	fi
	[ "$num" -eq "$num" ] 2>/dev/null
	if [ $? -ne 0 ]; then
		bail "invalid $type: $num" $line
	fi

	return 0
}

## global variables used to return values to callers
_ID=-1
_TYPE="invalid"
_LOGIN=""
_UID=-1
_GID=-1
_NGROUPS=-1
_GROUPS=""

## get_persona_info {persona_id} {persona_login}
#
# Lookup persona info for the given ID/login. At least one of the ID/login
# parameters must be valid
function get_persona_info() {
	local pna_id=${1:-1}
	local pna_login=${2:- }
	local line=$3
	if [ -z "$line" ]; then
		line=${BASH_LINENO[0]}
	fi

	local largs="-u ${pna_id}"
	if [ "${pna_login}" != " " ]; then
		largs+=" -l ${pna_login}"
	fi

	_ID=-1
	_TYPE=-1
	_LOGIN=""
	_UID=-1
	_GID=-1
	_NGROUPS=-1
	_GROUPS=()

	local file="${TMPDIR}/plookup"

	${PERSONA_MGR} lookup ${largs} > "${file}"
	check_return "persona lookup of: ${largs}" $line

	_ID=$(cat "${file}" | grep "+id: " | head -1 | sed 's/.*+id:[ ]*\([0-9][0-9]*\).*/\1/')
	test_num "Persona ID lookup:${largs}" "$_ID"

	local type=$(cat "${file}" | grep "+type: " | head -1 | sed 's/.*+type:[ ]*\([0-9][0-9]*\).*/\1/')
	test_num "+type lookup:${largs}" "$type"
	##
	## NOTE: keep in sync with bsd/sys/persona.h types!
	##
	if [ $type -eq 1 ]; then
		_TYPE=guest
	elif [ $type -eq 2 ]; then
		_TYPE=managed
	elif [ $type -eq 3 ]; then
		_TYPE=priv
	elif [ $type -eq 4 ]; then
		_TYPE=system
	else
		_TYPE=invalid
	fi

	_LOGIN=$(cat "${file}" | grep "+login: " | head -1 | sed 's/.*+login:[ ]*"\([^"]*\)".*/\1/')
	if [ -z "$_LOGIN" ]; then
		bail "invalid login for pna_id:$_ID: '$_LOGIN'" $line
	fi

	# these are always the same
	_UID=$_ID

	_GID=$(cat "${file}" | grep "+gid: " | head -1 | sed 's/.*+gid:[ ]*\([0-9][0-9]*\).*/\1/')
	test_num "GID lookup:${largs}" "$_GID"

	_NGROUPS=$(cat "${file}" | grep "ngroups: " | head -1 | sed 's/.*ngroups:[ ]*\([0-9][0-9]*\)[ ][ ]*{.*}.*/\1/')
	test_num "NGROUPS lookup:${largs}" "$_NGROUPS"

	_GROUPS=( $(cat "${file}" | grep "ngroups: " | head -1 | sed 's/.*ngroups:[ ]*[0-9][0-9]*[ ][ ]*{[ ]*\([^ ].*\)[ ][ ]*}.*/\1/') )
	if [ $_NGROUPS -gt 0 ]; then
		if [ -z "${_GROUPS}" ]; then
			bail "lookup:${largs}: missing $_NGROUPS groups" $line
		fi
		if [ ${#_GROUPS[@]} -ne $_NGROUPS ]; then
			bail "lookup:${largs} wrong number of groups ${#_GROUPS[@]} != $_NGROUPS" $line
		fi
	fi
}

## validate_child_info [output_file] [persona_id] {uid} {gid} {groups}
#
# Parse the output of the 'persona_spawn' command and validate that
# the new child process is in the correct persona with the correct
# process attributes.
#
function validate_child_info() {
	local file=$1
	local pna_id=$2
	local uid=${3:--1}
	local gid=${4:--1}
	local groups=${5:- }
	local line=$6
	if [ -z "$line" ]; then
		line=${BASH_LINENO[0]}
	fi
	local l=( )

	# get the child's PID
	local cpid="$(cat "$file" | grep "Child: PID:" | sed 's/.*Child: PID:\([0-9][0-9]*\).*/\1/')"
	test_num "Child PID" "$cpid" $line

	# validate the child's persona
	l=( $(cat "$file" | grep "Child: Persona:" | sed 's/.*Child: Persona: \([0-9][0-9]*\) (err:\([0-9][0-9]*\))/\1 \2/') )
	if [ ${#l[@]} -ne 2 ]; then
		bail "Invalid Child[$cpid] Persona line" $line
	fi
	test_num "Child Persona ID" "${l[0]}" $line
	test_num "kpersona_info retval" "${l[1]}" $line

	if [ ${l[0]} -ne $pna_id ]; then
		bail "Child[$cpid] persona:${l[0]} != specified persona:$pna_id" $line
	fi

	# Validate the UID/GID
	l=( $(cat "$file" | grep "Child: UID:" | sed 's/.*UID:\([0-9][0-9]*\), GID:\([0-9][0-9]*\).*/\1 \2/') )
	if [ ${#l[@]} -ne 2 ]; then
		bail "Invalid Child[$cpid] UID/GID output" $line
	fi
	if [ $uid -ge 0 ]; then
		if [ $uid -ne ${l[0]} ]; then
			bail "Child[$cpid] UID:${l[0]} != specified UID:$uid" $line
		fi
	fi
	if [ $gid -ge 0 ]; then
		if [ $gid -ne ${l[1]} ]; then
			bail "Child[$cpid] GID:${l[1]} != specified GID:$gid" $line
		fi
	fi

	# TODO: validate / verify groups?

	return 0
}


## spawn_child [persona_id] {uid} {gid} {group_spec}
#
# Create a child process that is spawn'd into the persona given by
# the first argument (pna_id). The new process can have its UID, GID,
# and group membership properties overridden.
#
function spawn_child() {
	local pna_id=$1
	local uid=${2:--1}
	local gid=${3:--1}
	local groups=${4:- }
	local line=$5
	if [ -z "$line" ]; then
		line=${BASH_LINENO[0]}
	fi

	local file="child.${pna_id}"
	local spawn_args="-I $pna_id"
	if [ $uid -ge 0 ]; then
		spawn_args+=" -u $uid"
		file+=".u$uid"
	fi
	if [ $gid -ge 0 ]; then
		spawn_args+=" -g $gid"
		file+=".g$gid"
	fi
	if [ "$groups" != " " ]; then
		spawn_args+=" -G $groups"
		file+="._groups"
	fi

	echo "SPAWN: $file"
	${PERSONA_SPAWN} -v $spawn_args ${PERSONA_SPAWN} child -v -E > "${TMPDIR}/$file"
	check_return "child info: $file" $line

	# Grab the specified persona's info so we can
	# verify the child's info against it.
	# This function puts data into global variables, e.g. _ID, _GID, etc.
	get_persona_info ${pna_id} " " $line
	if [ $uid -lt 0 ]; then
		uid=$_UID
	fi
	if [ $gid -lt 0 ]; then
		gid=$_GID
	fi
	if [ "$groups" == " " ]; then
		# convert a bash array into a comma-separated list for validation
		local _g="${_GROUPS[@]}"
		groups="${_g// /,}"
	fi

	validate_child_info "${TMPDIR}/$file" "$pna_id" "$uid" "$gid" "$groups" $line

	## TODO: validate that the first child spawned into a persona *cannot* spawn
	## into a different persona...
	##if [ $uid -eq 0 ]; then
	##	${PERSONA_SPAWN} -v $spawn_args ${PERSONA_SPAWN} child -v -E -R -v -I 99 /bin/echo "This is running in the system persona"
	##	expect_failure "Spawned child that re-execs into non-default persona" $line
	##fi
	return 0
}

## get_created_id [output_file]
#
# Parse the output of the 'persona_mgr' command to determine the ID
# of the newly created persona.
#
function get_created_id() {
	local file=$1
	local o=$(cat "$file" | grep "Created persona" | sed 's/.*Created persona \([0-9][0-9]*\):/\1/')
	echo $o
	return 0
}

## create_persona [login_name] [persona_type] {persona_id} {gid} {group_spec}
#
# Create a new persona with given parameters.
#
# Returns: the newly created persona ID via the global variable, $_ID
#
function create_persona() {
	local name=${1}
	local type=${2}
	local pna_id=${3:--1}
	local gid=${4:--1}
	local groups=${5:- }
	local line=$6
	if [ -z "$line" ]; then
		line=${BASH_LINENO[0]}
	fi

	if [ -z "$name" -o -z "$type" ]; then
		bail "Invalid arguments to create_persona '$name' '$type'" $line
	fi

	local file="persona.at${line}"
	# persona ID of '-1' is auto-assigned
	local spawn_args="-v -l $name -i $pna_id"
	if [ $pna_id -eq -1 ]; then
		file+=".auto"
	else
		file+=".${pna_id}"
	fi

	spawn_args+=" -t $type"
	file+=".$type"

	if [ $gid -ge 0 ]; then
		spawn_args+=" -g $gid"
		file+=".g$gid"
	fi
	if [ "$groups" != " " ]; then
		spawn_args+=" -G $groups"
		file+="._groups"
	fi

	echo "CREATE: $file"
	${PERSONA_MGR} create ${spawn_args} > "${TMPDIR}/${file}"
	check_return "persona creation: ${file}" $line
	# test output should include persona creation output for later debugging
	cat "${TMPDIR}/${file}"

	# validate the output of the persona_mgr tool (what we think we created)
	_ID=`get_created_id "${TMPDIR}/${file}"`
	test_num "persona_id for $file" "$_ID" $line
	if [ ${pna_id} -gt 0 ]; then
		if [ $_ID -ne ${pna_id} ]; then
			bail "Created persona doesn't have expected ID $_ID != ${pna_id}" $line
		fi
	fi

	# validate the entire persona information (what a kpersona_lookup says we created)
	# This function puts data into global variables, e.g. _ID, _LOGIN, _GID, etc.
	echo "VALIDATE: ${file}"
	get_persona_info ${pna_id} "$name" $line
	if [ "$name" != "$_LOGIN" ]; then
		bail "${file}: unexpected login '$_LOGIN' != '$name'" $line
	fi
	if [ "$type" != "$_TYPE" ]; then
		bail "${file}: unexpected type '$_TYPE' != '$type'" $line
	fi
	if [ ${pna_id} -gt 0 ]; then
		if [ ${pna_id} -ne $_ID ]; then
			bail "${file}: unexpected ID '$_ID' != '${pna_id}'" $line
		fi
	fi
	if [ $gid -ge 0 ]; then
		if [ $gid -ne $_GID ]; then
			bail "${file}: unexpected GID '$_GID' != '$gid'" $line
		fi
	fi
	if [ "$groups" != " " ]; then
		local _g="${_GROUPS[@]}"
		if [ "${_g// /,}" != "$groups" ]; then
			bail "${file}: unexpected groups '${_g// /,}' != '$groups'" $line
		fi
	fi

	return 0
}

## destroy_persona [persona_id]
#
# Destroy the given persona.
#
function destroy_persona() {
	local pna_id=$1
	local line=$2
	if [ -z "$line" ]; then
		line=${BASH_LINENO[0]}
	fi

	echo "DESTROY: ${pna_id}"
	${PERSONA_MGR} destroy -v -i ${pna_id}
	check_return "destruction of ${pna_id}" $line
}

#
#
# Begin Tests!
#
#
echo "Running persona tests [$LINENO] ($TMPDIR)"

##
## Test Group 0: basic creation + spawn tests
##

# default group, specific ID
create_persona "test0_1" "guest" 1001
P0ID=$_ID
spawn_child $P0ID
spawn_child $P0ID 1100
spawn_child $P0ID 0
spawn_child $P0ID -1 1101
spawn_child $P0ID 1100 1101
spawn_child $P0ID 1100 1101 1000,2000,3000
spawn_child $P0ID 1100 -1 1000,2000,3000
spawn_child $P0ID -1 -1 1000,2000,3000
destroy_persona $P0ID

# specific ID, non-default group
create_persona "test0_2" "guest" 1002 2000
P0ID=$_ID
spawn_child $P0ID
spawn_child $P0ID 1100
spawn_child $P0ID 0
spawn_child $P0ID -1 1101
spawn_child $P0ID 1100 1101
spawn_child $P0ID 1100 1101 1000,2000,3000
spawn_child $P0ID 1100 -1 1000,2000,3000
spawn_child $P0ID -1 -1 1000,2000,3000
destroy_persona $P0ID

# non-default set of groups
create_persona "test0_3" "guest" 1003 2000 2000,3000,4000
P0ID=$_ID
spawn_child $P0ID
spawn_child $P0ID 1100
spawn_child $P0ID 0
spawn_child $P0ID -1 1101
spawn_child $P0ID 1100 1101
spawn_child $P0ID 1100 1101 1111,2222,3333
spawn_child $P0ID 1100 -1 1111,2222,3333
spawn_child $P0ID -1 -1 1111,2222,3333
destroy_persona $P0ID


##
## Test Group 1: persona creation / re-creation
##

# Create 3 personas with auto-assigned IDs
create_persona "test1_1" "guest"
P1ID=$_ID
create_persona "test1_2" "managed"
P2ID=$_ID
create_persona "test1_3" "priv"
P3ID=$_ID
create_persona "test1_4" "system"
P4ID=$_ID

D1=$(($P2ID - $P1ID))
D2=$(($P3ID - $P2ID))
D3=$(($P4ID - $P3ID))
if [ $D1 -ne $D2 -o $D1 -ne $D3 -o $D2 -ne $D3 ]; then
	bail "inconsistent automatic Persona ID increment: $D1,$D2,$D3 ($P1ID,$P2ID,$P3ID,$P4ID)"
fi

# make sure we can't re-allocate the same name / ID
${PERSONA_MGR} create -v -l test1_1 -t guest -i -1 && expect_failure "re-create same name:test1_1 type:guest"
${PERSONA_MGR} create -v -l test1_1 -t managed -i -1 && expect_failure "re-create same name:test1_1 type:managed"
${PERSONA_MGR} create -v -l test1_1_new -t managed -i $P1ID && expect_failure "re-create $P1ID with new name:test1_1_new type:managed"

##
## Test Group 2: auto-assigned ID tricks
##

# Notice the difference in IDs, then try to create a persona by
# specifying an ID that will match the next auto-assigned ID
# (should succeed)
P5ID_REQ=$(($P4ID + $D2))
create_persona "test2_1" "guest" ${P5ID_REQ}
P5ID=$_ID
if [ ! $P5ID -eq ${P5ID_REQ} ]; then
	bail "test2_1: ${P5ID_REQ} != $P5ID"
fi

# try to create a persona with auto-assigned ID
# (resulting persona should have ID != P5ID)
create_persona "test2_2" "guest"
P6ID=$_ID
if [ $P6ID -eq $P5ID ]; then
	bail "created duplicate persona IDs: $P6ID == $P5ID"
fi

##
## Test Group 3: persona destruction
##

destroy_persona $P1ID
destroy_persona $P2ID
destroy_persona $P3ID
destroy_persona $P4ID
destroy_persona $P5ID
destroy_persona $P6ID

# try to re-destroy the personas
# (should fail)
${PERSONA_MGR} destroy -v -i $P1ID && expect_failure "re-destroy (1/2) $P1ID"
${PERSONA_MGR} destroy -v -i $P1ID && expect_failure "re-destroy (2/2) $P1ID"
${PERSONA_MGR} destroy -v -i $P2ID && expect_failure "re-destroy $P2ID"
${PERSONA_MGR} destroy -v -i $P3ID && expect_failure "re-destroy $P3ID"
${PERSONA_MGR} destroy -v -i $P4ID && expect_failure "re-destroy $P4ID"
${PERSONA_MGR} destroy -v -i $P5ID && expect_failure "re-destroy $P5ID"
${PERSONA_MGR} destroy -v -i $P6ID && expect_failure "re-destroy $P6ID"

# cleanup
rm -rf "${TMPDIR}"

echo ""
echo "${0##/}: SUCCESS"
exit 0
