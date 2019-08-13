# Efficient gas calculation algorithm for EVM

This article describes how to efficiently calculate gas and check stack requirements
for Ethereum Virtual Machine (EVM) instructions.


## Instructions metadata

Let's start by defining some basic and universal instructions' parameters.

1. Base gas cost.
   
   This is the static gas cost of instructions. Some instructions may have 
   additional cost depending on their operand values - these have to be
   handled individually during the instruction execution.
   
2. Stack height requirement.

   This is the minimum stack height (number of items on the stack) 
   required for the instruction execution.
   
3. Stack height change.

   This is difference of the stack height before and after the instruction 
   execution. Can be negative if the instruction pops more items than pushes.
   
Examples:

| opcode  | base gas cost | stack height requirement | stack height change |
| ------- | ------------- | ------------------------ | ------------------- |
| ADD     | 3             | 2                        | -1                  |
| EXP     | 50            | 2                        | -1                  |
| DUP4    | 3             | 4                        | 1                   |
| SWAP1   | 3             | 2                        | 0                   |
| ADDRESS | 2             | 0                        | 1                   |
| CALL    | 700           | 7                        | -6                  |


## Basic blocks

A _basic block_ is a sequence of instructions that are executed "straight-line"
without being interrupted by jumps. I.e. they are nodes in the _control flow graph_.

The name "basic block" has been taken from LLVM. Other names are: just "block"
in wasm or "subroutine" in subroutine-threaded interpreters.

In EVM there are simple rules to identify basic block boundaries:

1. The following instructions _end_ a basic block:
   - `JUMP`,
   - `JUMPI`,
   - `STOP`,
   - `RETURN`,
   - `REVERT`,
   - `SELFDESTRUCT`,
   - an instruction directly preceding `JUMPDEST`.

2. The following instructions _start_ a basic block:
   - `JUMPDEST`,
   - the first instruction in the code,
   - an instruction directly after an instruction that has ended previous basic block.


## Algorithm

The algorithm for calculating gas and checking stack requirements precomputes
the values for basic blocks and during execution the checks are done once per block.

### Collecting requirements for basic blocks

For a basic block we need to collect following information:

- total base gas required by instructions,
- the stack height required (the minimum stack height needed to execute 
  all instructions in the block),
- ~~the start-to-end stack height change~~,
- the relative maximum stack height.

This is done as follows:

1. Split code into basic blocks.
2. For each basic block:

```python
class Instruction:
    gas_required = 0
    stack_required = 0
    stack_change = 0

class BasicBlock:
    gas_required = 0
    stack_required = 0
    stack_change = 0  # FIXME: We don't have too keep it.
    stack_max = 0

def collect_basic_block_requirements(basic_block):
    for instruction in basic_block:
        basic_block.gas_required += instruction.gas_required
        
        current_stack_required = instruction.stack_required - basic_block.stack_change
        basic_block.stack_required = max(basic_block.stack_required, current_stack_required)
        
        basic_block.stack_change += instruction.stack_change
        
        basic_block.stack_max = max(basic_block.stack_max, basic_block.stack_change)
```

### Checking basic block requirements

During execution, before executing an instruction that starts a basic block,
the basic block requirements must be checked.

```python
class ExecutionState:
    gas_left = 0
    stack = []

def check_basic_block_requirements(state, basic_block):
    state.gas_left -= basic_block.gas_required
    if state.gas_left < 0:
        raise OutOfGas()
    
    if len(state.stack) < basic_block.stack_required:
        raise StackUnderflow()
    
    if len(state.stack) + basic_block.stack_max > 1024:
        raise StackOverflow()
```

## Misc

### EVM may terminate earlier

Because requirements for a whole basic blocks are checked up front, the instructions
that have observable external effects might not be executed although they would be
executed if the gas counting would have been done per instruction.
This is not a consensus issue because the execution terminates with a "hard" exception
anyway (and all effects are reverted) but might produce unexpected traces 
or terminate with a different exception type.

### Current "gas left" value

In EVMJIT also `GAS` and _call_ instructions begin a basic block. This is because
these instructions need to know the precise _gas left_ counter value. 
However, in evmone this problem has been solved without additional blocks splitting 
by attaching the correction value to the mentioned instructions.









   