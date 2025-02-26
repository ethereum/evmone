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

        let padded_base_len := mul(div(add(base_len, 31), 32), 32)
        let padded_mod_len := mul(div(add(mod_len, 31), 32), 32)
        let padded_exp_len := mul(div(add(exp_len, 31), 32), 32)

        let base_len_rem := mod(base_len, 32)
        let mod_len_rem := mod(mod_len, 32)
        let exp_len_rem := mod(exp_len, 32)

        let data := allocate(add(add(padded_base_len, padded_mod_len), padded_exp_len))

        let base_offset_in_calldata := 96
        let base_offset_in_mem := data
        if base_len_rem
        {
            base_offset_in_mem := add(base_offset_in_mem, sub(32, base_len_rem))
        }

        calldatacopy(base_offset_in_mem, base_offset_in_calldata, base_len)

        base_offset_in_mem := data

        let exp_offset_in_calldata := add(base_offset_in_calldata, base_len)
        let exp_offset_in_mem := add(base_offset_in_mem, base_len)
        if exp_len_rem
        {
            exp_offset_in_mem := add(exp_offset_in_mem, sub(32, exp_len_rem))
        }

        calldatacopy(exp_offset_in_mem, exp_offset_in_calldata, exp_len)

        exp_offset_in_mem := add(base_offset_in_mem, base_len)

        let mod_offset_in_calldata := add(exp_offset_in_calldata, exp_len)
        let mod_offset_in_mem := add(exp_offset_in_mem, exp_len)
        if mod_len_rem
        {
            mod_offset_in_mem := add(mod_offset_in_mem, sub(32, mod_len_rem))
        }
        calldatacopy(mod_offset_in_mem, mod_offset_in_calldata, mod_len)

        mod_offset_in_mem := add(exp_offset_in_mem, exp_len)

        // modulus is odd or power of two
        if or(and(1, calldataload(sub(cds, 32))), is_power_of_two(mod_offset_in_mem, padded_mod_len))
        {
            let res_ptr := calc_odd_modulus(base_offset_in_mem, padded_base_len, exp_offset_in_mem, padded_exp_len, mod_offset_in_mem, padded_mod_len)
            return(res_ptr, mod_len)
        }

        let N_offset, N_size, K_offset, K_size := decompose_to_odd_and_pow2(mod_offset_in_mem, padded_mod_len)
        let pow2_mem, pow2_size := one_to_pow2(255)

        let res_N := calc_odd_modulus(base_offset_in_mem, padded_base_len, exp_offset_in_mem, padded_exp_len, N_offset, N_size)
        let res_K := calc_odd_modulus(base_offset_in_mem, padded_base_len, exp_offset_in_mem, padded_exp_len, K_offset, K_size)

        storex(3, N_offset, 1)
        invmodx(0, 0, 3, 0, 1)
        storex(1, res_N, 1)
        storex(2, res_K, 1)

        submodx(2, 0, 2, 0, 1, 0, 1)
        mulmodx(2, 0, 2, 0, 0, 0, 1)

        let tmp_mem := allocate(K_size)
        loadx(tmp_mem, 2, 1)

        setmodx(pow2_mem, pow2_size, 3)

        storex(0, tmp_mem, 1) // (((x2 - x1) * N_inv) % K)
        storex(1, res_N, 1) // x1
        storex(2, N_offset, 1) // N
        mulmodx(2, 0, 0, 0, 2, 0, 1)
        addmodx(0, 0, 1, 0, 2, 0, 1)

        loadx(mod_offset_in_mem, 0, 1)
        return(mod_offset_in_mem, mod_len)

        function decompose_to_odd_and_pow2(_mem_offset, _mem_len) -> _N_offset, _N_size, _K_offset, _K_size
        {
            let mod_tailing_zeros := ctz(_mem_offset, _mem_len)

            _N_offset := _mem_offset
            _N_size := _mem_len

            shr_mem(_mem_offset, _mem_len, mod_tailing_zeros)
            _K_offset, _K_size := one_to_pow2(mod_tailing_zeros)
        }

        function shr_mem(_mem_offset, _mem_len, shift)
        {
            if mod(_mem_len, 32)
            {
                revert(0, 0)
            }

            let num_words := div(_mem_len, 32)
            let carry := 0

            for { let i := 0 } lt(i, num_words) { i := add(i, 1) }
            {
                let word := mload(add(_mem_offset, mul(i, 32)))
                mstore(add(_mem_offset, mul(i, 32)), or(shr(shift, word), carry))
                carry := shl(sub(256, shift), word)
            }
        }

        function one_to_pow2(k) -> mem_ptr, mem_len
        {
            let num_words := div(add(k, 255), 256)
            mem_len := mul(num_words, 32)
            mem_ptr := allocate(mem_len)
            let word_index := div(k, 256)
            let shift := mod(k, 256)
            let word := shl(shift, 1)

            mstore(sub(add(mem_ptr, mem_len), mul(add(word_index, 1), 32)), word)
        }

        function ctz(_mem_offset, _mem_len) -> ret
        {
            if mod(_mem_len, 32)
            {
                revert(0, 0)
            }

            let num_words := div(_mem_len, 32)

            let num_bits := mul(_mem_len, 8)
            for { let i := 0 } lt(i, num_words) { i := add(i, 1) }
            {
                let word := mload(add(_mem_offset, mul(i, 32)))
                if word
                {
                    ret := mul(256, sub(num_words, add(1, i)))
                    ret := add(ret, ctz_word(word))
                }
            }
        }

        function ctz_word(v) -> ret
        {
            ret := 0
            for { let i := 0 } lt(i, 256) { i := add(i, 1) }
            {
                if and(v, 1)
                {
                    leave
                }
                v := shr(1, v)
                ret := add(ret, 1)
            }
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

        function is_power_of_two(_mem_offset, _mem_len) -> ret
        {
            let num_words := div(_mem_len, 32)

            ret := 0
            for { let i := 0 } lt(i, num_words) { i := add(i, 1) }
            {
                 let word := mload(add(_mem_offset, mul(i, 32)))
                 if word
                 {
                    if or(ret, and(word, sub(word, 1)))
                    {
                        ret := 0
                        leave
                    }

                    ret := 1
                 }
            }
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
                for {} mask { mask := shr(1, mask) }
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
