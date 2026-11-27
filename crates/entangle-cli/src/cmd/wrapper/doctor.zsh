# Inspect the invoking shell when doctor runs. The saved definition stays local.
__entangle_claude_definition=${functions[claude-code]}
if (( ! ${+aliases[entangle]} && ! ${+functions[entangle]} )); then
  function entangle {
    if [[ ${1-} == doctor || ( ${1-} == --allow-local && ${2-} == doctor ) ]]; then
      local resolution=shadowed
      if [[ $(whence -w -- claude-code) == 'claude-code: function' && ${functions[claude-code]} == "$__entangle_claude_definition" ]]; then
        resolution=active
      fi
      ENTANGLE_WRAPPER_RESOLUTION="$resolution" command entangle "$@"
    else
      command entangle "$@"
    fi
  }
fi
