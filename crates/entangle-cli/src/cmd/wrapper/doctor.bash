# Inspect the invoking shell when doctor runs. The saved definition stays local.
__entangle_claude_definition=$(declare -f -- claude-code)
if ! alias entangle >/dev/null 2>&1 && ! declare -F -- entangle >/dev/null; then
  function entangle {
    if [[ ${1-} == doctor || ( ${1-} == --allow-local && ${2-} == doctor ) ]]; then
      local resolution=shadowed
      if [[ $(type -t -- claude-code) == function && $(declare -f -- claude-code) == "$__entangle_claude_definition" ]]; then
        resolution=active
      fi
      ENTANGLE_WRAPPER_RESOLUTION="$resolution" command entangle "$@"
    else
      command entangle "$@"
    fi
  }
fi
