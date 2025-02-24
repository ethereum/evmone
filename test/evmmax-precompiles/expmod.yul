object "expmod" {
    code {
        let cds := calldatasize()

        if lt(cds, 96)
        {
            revert(0, 0)
        }

        let base_len := calldataload(0)
        let exp_len := calldataload(32)
        let mod_len := calldataload(64)

        if iszero(eq(cds, add(96, add(add(base_len, exp_len), mod_len))))
        {
            revert(0, 0)
        }

        if mod(exp_len, 32)
        {
            revert(0, 0)
        }

        let data := allocate(add(add(base_len, exp_len), mod_len))

        let base_offset_in_calldata := 96
        let base_offset_in_mem := data
        calldatacopy(base_offset_in_mem, base_offset_in_calldata, base_len)

        let exp_offset_in_calldata := add(base_offset_in_calldata, base_len)
        let exp_offset_in_mem := add(base_offset_in_mem, base_len)
        calldatacopy(exp_offset_in_mem, exp_offset_in_calldata, exp_len)

        let mod_offset_in_calldata := add(exp_offset_in_calldata, exp_len)
        let mod_offset_in_mem := add(exp_offset_in_mem, exp_len)
        calldatacopy(mod_offset_in_mem, mod_offset_in_calldata, mod_len)

        if and(1, calldataload(sub(calldatasize(), 32))) // modulus is odd
        {
            let res_ptr := calc_odd_modulus(base_offset_in_mem, base_len, exp_offset_in_mem, exp_len, mod_offset_in_mem, mod_len)
            return(res_ptr, mod_len)
        }

        function allocate(_size) -> ptr
        {
            ptr := mload(0x40)
            // Note that Solidity generated IR code reserves memory offset ``0x60`` as well, but a pure Yul object is free to use memory as it chooses.
            if iszero(ptr) { ptr := 0x60 }
            mstore(0x40, add(ptr, _size))
        }

        function init_one(_mod_len)
        {
            let mod_num_words := div(_mod_len, 32)

            let ptr := allocate(_mod_len)

            for { let i := 0 } iszero(gt(i, mod_num_words)) { i := add(i, 1) }
            {
                mstore(add(ptr, mul(i, 32)), 0)
            }

            mstore8(add(ptr, sub(_mod_len, 1)), 1)

            storex(1, ptr, 1)
        }

        function calc_odd_modulus(_base_mem_offset, _base_len, _exp_mem_offset, _exp_len, _mod_mem_offset, _mod_len) -> ptr
        {
            setmodx(_mod_mem_offset, _mod_len, 256)
            storex(0, _base_mem_offset, 1)

            init_one(_mod_len)

            let exp_num_words := div(_exp_len, 32)

            for { let i := 0 } lt(i, exp_num_words) { i := add(i, 1) }
            {
                let e := mload(add(_exp_mem_offset, mul(i, 32)))
                let mask := shl(255, 1)
                for { let j := 0 } mask { mask := shr(1, mask) }
                {
                    mulmodx(1, 0, 1, 0, 1, 0, 1)
                    if and(mask, e)
                    {
                        mulmodx(1, 0, 1, 0, 0, 0, 1)
                    }
                }
            }

            ptr := allocate(_mod_len)
            loadx(ptr, 1, 1)
        }
    }
}
