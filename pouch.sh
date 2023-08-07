#!/usr/bin/env bash

# Copyright (c) 2018-2020 drduh.

set -o errtrace
set -o nounset
set -o pipefail

# set -x # uncomment to debug

umask 077

now=$(date +%s)
age="$(command -v age || command -v rage)"
copy="$(command -v xclip || command -v pbcopy)"
safeix="${POUCH_INDEX:=pouch.index}"
safedir="${POUCH_SAFE:=safe}"
timeout=45

fail() {
  # Print an error message and exit.

  tput setaf 1 1 1
  printf "\nError: %s\n" "${1}"
  tput sgr0
  exit 1
}

read_pass() {
  # Read a password from safe.

  if [[ ! -s ${safeix} ]]; then fail "${safeix} not found"; fi

  if [[ -z "${2+x}" ]]; then
    username="$(gum input --prompt "Username: ")"
  else username="${2}"; fi

  if [[ -z "${username}" ]]; then
    fail "Username not provided"
  fi

  spath=$(grep -F "${username}" "${safeix}" |
    tail -n1 | cut -d ":" -f2)

  readpass=$(cat "${spath}" | ${age} -d -i ${POUCH_AGE_IDENTITY} | head -n1) ||
    fail "Decryption failed"

  clip <(printf "$readpass") || fail "Copy to clipboard failed"
}

gen_pass() {
  # Generate a password using openssl.

  len=20
  max=80

  if [[ -z "${3+x}" ]]; then
    length="$(gum input --prompt "Password length (default: ${len}, max: ${max}): ")"
  else length="${3}"; fi

  if [[ ${length} =~ ^[0-9]+$ ]]; then len=${length}; fi

  # Improve this with eff wordlist passphrase generation
  openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c "$length"
}

write_pass() {
  # Write a password and update index file.

  fpath=$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 8)
  spath=${safedir}/${fpath}

  printf '%s\n' "${userpass}" |
    ${age} -e -r ${POUCH_AGE_RECIPIENT} -a -o "${spath}" ||
    fail "Failed to put ${spath}"

  printf "%s@%s:%s\n" "${username}" "${now}" "${spath}" >>"${safeix}"
}

list_entry() {
  if [[ ! -s ${safeix} ]]; then fail "${safeix} not found"; fi

  cat "${safeix}"
}

clip() {
  # Use clipboard and clear after timeout.

  ${copy} <"${1}"

  shift
  while [ $timeout -gt 0 ]; do
    printf "\r\033[KPassword on clipboard! Clearing in %.d" $((timeout--))
    sleep 1
  done

  printf "" | ${copy}
}

new_entry() {
  # Prompt for new username and/or password.

  if [[ -z "${2+x}" ]]; then
    username="$(gum input --prompt "Username: " --placeholder "name@example.com")"
  else username="${2}"; fi

  if [[ -z "${username}" ]]; then
    fail "Username not provided"
  fi

  if [[ -z "${3+x}" ]]; then
    password="$(gum input --password --prompt "Password for \"${username}\" (Enter to generate): ")"
    userpass="${password}"
  fi

  if [[ -z "${password}" ]]; then userpass=$(gen_pass "$@"); fi
}

print_help() {
  # Print help text.

  printf """
  Pouch is a Bash shell script to manage passwords with age encryption.

  Pouch can be used by passing one of the following options:

    * '-w' to write a password
    * '-r' to read a password
    * '-l' to list passwords

  Example usage:

    * Generate a 30 character password for 'userName':
        ./pouch.sh -w userName 30

    * Copy the password for 'userName' to clipboard:
        ./pouch.sh -r userName

    * List stored passwords and copy a previous version:
        ./pouch.sh -l
        ./pouch.sh -r userName@1574723625"""
}

if [[ -z ${age} && ! -x ${age} ]]; then fail "age is not available"; fi

if [[ -z ${copy} && ! -x ${copy} ]]; then fail "Clipboard is not available"; fi

if [[ ! -d ${safedir} ]]; then mkdir -p ${safedir}; fi

chmod -R 0600 ${safeix} 2>/dev/null
chmod -R 0700 ${safedir} 2>/dev/null

password=""
action=""
if [[ -n "${1+x}" ]]; then action="${1}"; fi

case "$action" in
"-r")
  read_pass "$@"
  ;;

"-w")
  new_entry "$@"
  write_pass
  ;;

"-f")
  filter_entry
  ;;

"-l")
  list_entry
  ;;

"-h" | *)
  print_help
  ;;
esac

chmod -R 0400 ${safeix} ${safedir} 2>/dev/null
