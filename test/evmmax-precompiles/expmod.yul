object "expmod" {
    code {
        let base_ptr, base_len, exp_ptr, exp_len, mod_ptr, mod_len := process_input_data()

        // modulus is odd or power of two
        if or(and(1, calldataload(sub(calldatasize(), 32))), is_power_of_two(mod_ptr, mod_len))
        {
            let res_ptr := expmod_impl(base_ptr, base_len, exp_ptr, exp_len, mod_ptr, mod_len)
            return(res_ptr, mod_len)
        }

        let even_mod_result := expmod_even_impl(base_ptr, base_len, exp_ptr, exp_len, mod_ptr, mod_len)

        return(even_mod_result, mod_len)

        function process_input_data() -> _base_ptr, _base_len, _exp_ptr, _exp_len, _mod_ptr, _mod_len
        {
            let cds := calldatasize()

            let base_calldata_len := calldataload(0)
            let exp_calldata_len := calldataload(32)
            let mod_calldata_len := calldataload(64)

            _base_ptr, _base_len := copy_calldata_32_padded(96, base_calldata_len)
            _exp_ptr, _exp_len := copy_calldata_32_padded(add(96, base_calldata_len), exp_calldata_len)
            _mod_ptr, _mod_len := copy_calldata_32_padded(add(add(96, base_calldata_len), exp_calldata_len), mod_calldata_len)
        }

        function copy_calldata_32_padded(_src_calldata_ptr, _src_len) -> _dst_ptr, _dst_len
        {
            let _len_rem := mod(_src_len, 32)
            _dst_len := _src_len
            let dst_ptr_offset := 0
            if _len_rem
            {
                _dst_len := add(div(_src_len, 32), 1)
                dst_ptr_offset := sub(32, _len_rem)
            }

            _dst_ptr := allocate(_dst_len)

            calldatacopy(add(_dst_ptr, dst_ptr_offset), _src_calldata_ptr, _src_len)
        }

        function lowest_greater_pow2(_mem_offset, _mem_len) -> ret_offset, ret_len
        {
            let highest_word := mload(_mem_offset)
            if and(highest_word, shl(255, 1))
            {
                ret_len := add(_mem_len, 32)
                ret_offset := allocate(ret_len)
                mstore(ret_offset, 1)
                leave
            }

            ret_len := _mem_len
            ret_offset := allocate(ret_len)
            mstore(ret_offset, shl(255, 1))
        }

        function decompose_to_odd_and_pow2(_mem_offset, _mem_len) -> _N_offset, _N_size, _K_offset, _K_size
        {
            let mod_tailing_zeros := ctz_mem(_mem_offset, _mem_len)

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

        function ctz_mem(_mem_offset, _mem_len) -> ret
        {
            if mod(_mem_len, 32)
            {
                revert(0, 0)
            }

            let num_words := div(_mem_len, 32)

            let num_bits := mul(_mem_len, 8)
            let ptr := sub(add(_mem_offset, _mem_len), 32)
            ret := 0
            for { let i := 0 } lt(i, num_words) { i := add(i, 1) }
            {
                let word := mload(ptr)
                if iszero(word)
                {
                    ret := add(ret, 256)
                    ptr := sub(ptr, 32)
                    continue
                }

                ret := add(ret, ctz(word))
                leave
            }
        }

        function clz_mem(_mem_offset, _mem_len) -> ret
        {
            if mod(_mem_len, 32)
            {
                revert(0, 0)
            }

            let num_words := div(_mem_len, 32)

            let num_bits := mul(_mem_len, 8)
            let ptr := _mem_offset
            ret := 0
            for { let i := 0 } lt(i, num_words) { i := add(i, 1) }
            {
                let word := mload(ptr)
                if iszero(word)
                {
                    ret := add(ret, 256)
                    ptr := add(ptr, 32)
                    continue
                }

                ret := add(ret, clz(word))
                leave
            }
        }

        function ctz(x) -> n
        {
            if iszero(x)
            {
                n := 256
                leave
            }

            x := and(x, sub(0, x))
            n := sub(255, clz(x))
        }

        function clz(x) -> n
        {
            if iszero(x)
            {
                n := 256
                leave
            }

            n := 0
            if iszero(shr(128, x)) { n := add(n, 128) x := shl(128, x) }
            if iszero(shr(192, x)) { n := add(n, 64) x := shl(64, x) }
            if iszero(shr(224, x)) { n := add(n, 32) x := shl(32, x) }
            if iszero(shr(240, x)) { n := add(n, 16) x := shl(16, x) }
            if iszero(shr(248, x)) { n := add(n, 8) x := shl(8, x) }
            if iszero(shr(252, x)) { n := add(n, 4) x := shl(4, x) }
            if iszero(shr(254, x)) { n := add(n, 2) x := shl(2, x) }
            if iszero(shr(255, x)) { n := add(n, 1) x := shl(1, x) }
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

        function expmod_impl(_base_ptr, _base_len, _exp_ptr, _exp_len, _mod_ptr, _mod_len) -> ptr
        {
            setmodx(_mod_ptr, _mod_len, 256)
            storex(0, _base_ptr, 1)

            init_one(_mod_len)

            let exp_num_words := div(_exp_len, 32)

            let leading_zeros := clz_mem(_exp_ptr, _exp_len)

            let fist_non_zero_word := div(leading_zeros, 256)

            let fists_word := mload(add(_exp_ptr, mul(fist_non_zero_word, 32)))
            let first_mask := shl(sub(255, clz(fists_word)), 1)

            for {} first_mask { first_mask := shr(1, first_mask) }
            {
                mulmodx(1, 0, 1, 0, 1, 0, 1)
                if and(first_mask, fists_word)
                {
                    mulmodx(1, 0, 1, 0, 0, 0, 1)
                }
            }

            for { let i := add(fist_non_zero_word, 1) } lt(i, exp_num_words) { i := add(i, 1) }
            {
                let e := mload(add(_exp_ptr, mul(i, 32)))
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

        function expmod_even_impl(_base_ptr, _base_len, _exp_ptr, _exp_len, _mod_ptr, _mod_len) -> res_ptr
        {
            let N_ptr, N_len, K_ptr, K_len := decompose_to_odd_and_pow2(_mod_ptr, _mod_len)

            let x1_ptr := expmod_impl(_base_ptr, _base_len, _exp_ptr, _exp_len, N_ptr, N_len)
            let x2_ptr := expmod_impl(_base_ptr, _base_len, _exp_ptr, _exp_len, K_ptr, K_len)

            storex(3, N_ptr, 1)     // N^(-1) % 2^K
            invmodx(0, 0, 3, 0, 1)

            storex(1, x1_ptr, 1)
            storex(2, x2_ptr, 1)

            submodx(2, 0, 2, 0, 1, 0, 1)    // (x2 - x1) % 2^K
            mulmodx(2, 0, 2, 0, 0, 0, 1)    // (x2 - x1) * N^(-1) % 2^K

            let pow2_ptr, pow2_len := lowest_greater_pow2(_mod_ptr, _mod_len)   // modulus 2*L > input mod
            if iszero(eq(pow2_len, K_len))
            {
                let x1_ext_ptr := allocate(pow2_len)
                mcopy(x1_ext_ptr, x1_ptr, sub(pow2_len, N_len))
                x1_ptr := x1_ext_ptr

                let N_exp_ptr := allocate(pow2_len)
                mcopy(N_exp_ptr, N_ptr, sub(pow2_len, N_len))
                N_ptr := N_exp_ptr
            }

            let tmp_mem := allocate(pow2_len)  // load (x2 - x1) * N^(-1) % 2^K
            loadx(add(tmp_mem, sub(pow2_len, K_len)), 2, 1)

            setmodx(pow2_ptr, pow2_len, 3)

            storex(0, tmp_mem, 1)           // (((x2 - x1) * N_inv) % K)
            storex(1, x1_ptr, 1)            // x1
            storex(2, N_ptr, 1)             // N
            mulmodx(2, 0, 0, 0, 2, 0, 1)    // (((x2 - x1) * N_inv) % K) * N
            addmodx(0, 0, 1, 0, 2, 0, 1)    // x1 + (((x2 - x1) * N_inv) % K) * N

            res_ptr := allocate(_mod_len)
            loadx(res_ptr, 0, 1)
        }
    }
}
