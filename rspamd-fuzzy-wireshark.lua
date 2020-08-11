do -- scope
    local proto = Proto('fuzzy', 'RspamD fuzzy storage protocol')

    
    -- unit8_t version;        /* command version, must be 0x2 */
    -- unit8_t cmd;            /* numeric command */
    -- unit8_t shingles_count; /* number of shingles */
    -- unit8_t flag;           /* flag number */
    -- int32_t value;          /* value to store */
    -- uint32_t tag;           /* random tag */
    -- char digest[64];        /* blake2b digest */
    local vs_cmds = { 
        [0]= "FUZZY_CHECK",
        [1]= "FUZZY_ADD",
        [2]= "FUZZY_DEL"
    }
    local version = ProtoField.uint8("fuzzy.version", "version", base.DEC)
    local cmd = ProtoField.uint8("fuzzy.cmd", "cmd", base.DEC, vs_cmds)
    local shingles_count = ProtoField.uint8("fuzzy.shingles_count", "shingles_count", base.DEC)
    local flag = ProtoField.uint8("fuzzy.flag", "flag", base.DEC)
    local value = ProtoField.uint32("fuzzy.value", "value", base.DEC)
    local tag = ProtoField.uint32("fuzzy.tag", "tag", base.DEC)
    -- blake2b digest
    local digest = ProtoField.bytes("fuzzy.digest", "digest", base.SPACE)
    local oneShingle = ProtoField.uint64("fuzzy.shingle", "shingle", base.DEC)

    -- struct fuzzy_cmd  { /* attribute(packed) */
    -- int32_t value;
    -- uint32_t flag;
    -- uint32_t tag;
    -- float prob;
    -- };
    local prob = ProtoField.float("fuzzy.prob", "prob", base.DEC)

    
    proto.fields = { version, cmd, shingles_count, flag, value, tag,prob,digest, oneShingle}

    function proto.dissector(buffer, pinfo, tree)
        pinfo.cols.protocol = 'RspamD fuzzy'

        length = buffer:len()
        if length == 0 then return end
        
        
        local first_byte = buffer(0,1):uint()
        print("first_byte: " .. first_byte)
        if first_byte == 4 then
            local subtree = tree:add(proto, buffer(), proto.name .. " Data (request)")
            local sh_count = buffer(2,1):uint()
            subtree:add_le(version, buffer(0,1))
            subtree:add_le(cmd, buffer(1,1))
            subtree:add_le(shingles_count, sh_count)
            subtree:add_le(flag, buffer(3,1))
            subtree:add_le(value, buffer(4,4))
            subtree:add_le(tag, buffer(8,4))
            subtree:add_le(digest, buffer(12,64))
            local shingles_offset_start = 76
            local shingles_array = subtree:add(proto, buffer(shingles_offset_start,length-shingles_offset_start), "shingles [" .. sh_count .. "]")
            
            for i=0,sh_count-1 do
                local sh = shingles_array:add_le(oneShingle,buffer(shingles_offset_start + 8*i,8))
                sh:prepend_text('['.. i .. ']: ')
            end
        else
            local subtree = tree:add(proto, buffer(), proto.name .. " Data (reply)")
            subtree:add_le(value, buffer(0,4))
            subtree:add_le(flag, buffer(4,4))
            subtree:add_le(tag, buffer(8,4))
            subtree:add_le(prob, buffer(12,4))
            subtree:add_le(digest, buffer(16,64))
        end  

        


    end

    -- register this dissector for the standard rspamd-fuzzy ports
    local dissectors = DissectorTable.get('udp.port')
    for _, port in ipairs{ 11335, } do
        dissectors:add(port, proto)
    end
end
