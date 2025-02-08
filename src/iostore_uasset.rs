use base64::{prelude::BASE64_STANDARD, Engine};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::{cmp::Ordering, error::Error, fmt::Display, io::{BufRead, Cursor, Read, Seek, SeekFrom, Write}};

struct UObjectSummaryHeader {
    name: u64,     
    source_name: u64,
    package_flags: u32,
    cooked_header_size: u32,
    name_map_names_offset: i32,
    name_map_names_size: i32,
    name_map_hashes_offset: i32,
    name_map_hashes_size: i32,
    import_map_offset: i32,
    export_map_offset: i32,
    export_bundles_offset: i32,
    graph_data_offset: i32,
    graph_data_size: i32,
    pad: i32
}

impl UObjectSummaryHeader {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let name = reader.read_u64::<E>().unwrap();
        let source_name = reader.read_u64::<E>().unwrap();
        let package_flags = reader.read_u32::<E>().unwrap();
        let cooked_header_size = reader.read_u32::<E>().unwrap();
        let name_map_names_offset = reader.read_i32::<E>().unwrap();
        let name_map_names_size = reader.read_i32::<E>().unwrap();
        let name_map_hashes_offset = reader.read_i32::<E>().unwrap();
        let name_map_hashes_size = reader.read_i32::<E>().unwrap();
        let import_map_offset = reader.read_i32::<E>().unwrap();
        let export_map_offset = reader.read_i32::<E>().unwrap();
        let export_bundles_offset = reader.read_i32::<E>().unwrap();
        let graph_data_offset = reader.read_i32::<E>().unwrap();
        let graph_data_size = reader.read_i32::<E>().unwrap();
        reader.read_u32::<E>().unwrap(); //move reader past padding

        Ok(Self {
            name,
            source_name,
            package_flags,
            cooked_header_size,
            name_map_names_offset,
            name_map_names_size,
            name_map_hashes_offset,
            name_map_hashes_size,
            import_map_offset,
            export_map_offset,
            export_bundles_offset,
            graph_data_offset,
            graph_data_size,
            pad: 0
        })
    }

    pub fn to_bytes<E: byteorder::ByteOrder>(&self) -> Vec<u8> {
        let mut result = vec![];
        
        result.write_u64::<E>(self.name).unwrap();
        result.write_u64::<E>(self.source_name).unwrap();
        result.write_u32::<E>(self.package_flags).unwrap();
        result.write_u32::<E>(self.cooked_header_size).unwrap();
        result.write_i32::<E>(self.name_map_names_offset).unwrap();
        result.write_i32::<E>(self.name_map_names_size).unwrap();
        result.write_i32::<E>(self.name_map_hashes_offset).unwrap();
        result.write_i32::<E>(self.name_map_hashes_size).unwrap();
        result.write_i32::<E>(self.import_map_offset).unwrap();
        result.write_i32::<E>(self.export_map_offset).unwrap();
        result.write_i32::<E>(self.export_bundles_offset).unwrap();
        result.write_i32::<E>(self.graph_data_offset).unwrap();
        result.write_i32::<E>(self.graph_data_size).unwrap();
        result.write_i32::<E>(self.pad).unwrap();

        result
    }
}

enum StringType {
    Utf8,
    Utf16,
}


struct UObjectSummary {
    header: UObjectSummaryHeader,
    name_map: Vec<String>,
    name_map_type: Vec<StringType>,
    remaining_bytes: Vec<u8>,
}

impl UObjectSummary {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let header = UObjectSummaryHeader::from_buffer::<R, E>(reader)?;
        let names_count = (header.name_map_hashes_size/(std::mem::size_of::<u64>() as i32)) - 1;
        let mut name_map: Vec<String> = Vec::with_capacity(names_count as usize);
        let mut name_map_type: Vec<StringType> = Vec::with_capacity(names_count as usize);
        for _ in 0..names_count {
            let meta1 = reader.read_u8().unwrap();
            let meta2 = reader.read_u8().unwrap();

            let len = ((meta1 & 0x7f) as usize) * 256 + meta2 as usize;
            if meta1 & 0x80 > 0 { //utf16 marker
                if reader.stream_position().unwrap() % 2 > 0 { // for some reason utf16 names seem to only start at even positions
                    reader.read_u8().unwrap();
                }
                let mut raw_string = Vec::<u16>::with_capacity(len);
                for _ in 0..len {
                    raw_string.push(reader.read_u16::<E>().unwrap());
                }
                name_map.push(String::from_utf16(&raw_string).unwrap());
                name_map_type.push(StringType::Utf16);
            } else {
                let mut raw_string = vec![0;len];
                reader.read_exact(&mut raw_string).unwrap();
                name_map.push(String::from_utf8(raw_string).unwrap());
                name_map_type.push(StringType::Utf8);
            }
        }

        let pos = reader.stream_position().unwrap() as usize;
        let raw_byte_length = (header.graph_data_offset + header.graph_data_size) as usize;
        let mut raw_bytes = vec![0;raw_byte_length-pos];

        reader.read_exact(&mut raw_bytes).unwrap();
        
        Ok(Self {
            header,
            name_map,
            name_map_type,
            remaining_bytes: raw_bytes,
        })
    }

    pub fn to_bytes<E: byteorder::ByteOrder>(&self) -> Vec<u8> {
        let mut result = self.header.to_bytes::<E>();
        for i in 0..self.name_map.len() {
            let name = &self.name_map[i];
            match self.name_map_type[i] {
                StringType::Utf16 => {
                    let bytes: Vec<u16> = name.encode_utf16().collect();
                    result.push((bytes.len() / 256) as u8 | 0x80);
                    result.push((bytes.len() % 256) as u8);

                    if result.len() % 2 > 0 {
                        result.push(0);
                    }

                    for char in bytes {
                        result.write_u16::<E>(char).unwrap();
                    }
                },
                StringType::Utf8 => {
                    result.push((name.len() / 256) as u8);
                    result.push((name.len() % 256) as u8);
                    result.write_all(name.as_bytes()).unwrap();
                }
            }
        }
        
        result.write_all(&self.remaining_bytes).unwrap();

        result
    }

    pub fn from_string(str: &str) -> Result<Self, Box<dyn Error>> {
        let bytes = BASE64_STANDARD.decode(str).map_err(|_| "Unable to read object summary header from base64 string. This value shouldn't be manually edited.")?;
        let mut bytes = Cursor::new(bytes);
        Self::from_buffer::<_, LE>(&mut bytes)
    }
}

impl Display for UObjectSummary {    
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&BASE64_STANDARD.encode(self.to_bytes::<LE>()))
    }
}

#[derive(PartialEq, Debug)]
pub struct UObjectPropertyHeader {
    pub name: String,
    pub r#type: String,
    pub arr_index: usize,
}

impl UObjectPropertyHeader {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(reader: &mut R, name_map: &[String]) -> Option<(Self, usize)> {
        let name_index = reader.read_u64::<E>().unwrap() as usize;
        let name = name_map[name_index].clone();

        if name == "None" {
            return None;
        }

        let type_index = reader.read_u64::<E>().unwrap() as usize;
        let r#type = name_map[type_index].clone();

        let data_size = reader.read_u32::<E>().unwrap() as usize;
        let arr_index = reader.read_u32::<E>().unwrap() as usize;

        Some((Self {
            name,
            r#type,
            arr_index
        }, data_size))
    }

    pub fn to_bytes<W: Write, E: byteorder::ByteOrder>(&self, writer: &mut W, name_map: &[String], data_size: usize) -> bool {
        let name_index = name_map.iter().position(|n| n == &self.name).unwrap_or_else(|| panic!("Object type [{}] wasn't in name map", self.name)) as u64;
        if self.name == "None" {
            writer.write_u64::<E>(name_index).unwrap();
            false
        } else {
            let type_index = name_map.iter().position(|n| n == &self.r#type).unwrap_or_else(|| panic!("Object type [{}] wasn't in name map", self.r#type)) as u64;

            writer.write_u64::<E>(name_index).unwrap();
            writer.write_u64::<E>(type_index).unwrap();
            writer.write_u32::<E>(data_size as u32).unwrap();
            writer.write_u32::<E>(self.arr_index as u32).unwrap();
            true
        }
    }

    #[inline]
    pub fn byte_len() -> usize {
        8 + 8 + 4 + 4
    }
}

#[derive(PartialEq, Debug)]
pub struct UObjectProperty {
    header: UObjectPropertyHeader,
    metadata: UObjectPropertyMetadata,
    data: UObjectPropertyData,
}

impl UObjectProperty {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(reader: &mut R, name_map: &[String]) -> Result<Option<Self>, Box<dyn Error>> {
        match UObjectPropertyHeader::from_buffer::<R,E>(reader, name_map) {
            Some((header, expected_size)) => {
                let metadata = UObjectPropertyMetadata::from_buffer::<R,E>(reader, &header.r#type, name_map);
                let data = UObjectPropertyData::from_buffer::<R,E>(reader, &header.r#type, &metadata, name_map, expected_size)?;
                Ok(Some(Self {
                    header,
                    metadata,
                    data,
                }))
            },
            None => Ok(None)
        }
    }

    pub fn to_bytes<W: Write, E: byteorder::ByteOrder>(&self, writer: &mut W, name_map: &[String]) -> usize {
        let mut data = vec![];
        let data_size = self.data.to_bytes::<_,E>(&mut data, name_map);

        if self.header.to_bytes::<W,E>(writer, name_map, data_size) {
            let meta_len = self.metadata.to_bytes::<W,E>(writer, name_map);
            writer.write_all(&data).unwrap();
            UObjectPropertyHeader::byte_len() + data.len() + meta_len
        } else {
            UObjectPropertyHeader::byte_len()
        }
    }

    pub fn to_string<W: Write>(&self, writer: &mut W, indent_spaces: usize) {
        if self.header.arr_index == 0 {
            writer.write_all(format!("{}: ", self.header.name).as_bytes()).unwrap();
        } else {
            writer.write_all(format!("{}[{}]: ", self.header.name, self.header.arr_index).as_bytes()).unwrap();
        }
        self.data.to_string(&self.metadata, writer, indent_spaces);
    }

    pub fn from_string<R: BufRead + Seek>(reader: &mut R, expected_indent_level: usize) -> Result<Option<Self>, Box<dyn Error>> {
        let next_line = next_nonempty_line(reader);
        if next_line.is_empty() || !check_indent(&next_line, expected_indent_level) {
            reader.seek(SeekFrom::Current(-(next_line.len() as i64))).unwrap();
            return Ok(None);
        }

        let (name, val) = next_line.split_once(':').ok_or(format!("Missing ':' delimiter for property at position 0x{:x}", reader.stream_position().unwrap()))?;

        let (name, arr_index) = {
            let iter = name.trim().chars();
            let name = iter.clone().take_while(|c| *c != '[').collect::<String>();
            let mut iter = iter.skip_while(|c| *c != '[');
            let index = match iter.next() {
                Some(_) => { Some(iter.take_while(|c| *c != ']').collect::<String>().parse::<usize>()?) },
                None => None,
            };
            (name, index.unwrap_or(0))
        };

        let (data, metadata) = UObjectPropertyData::from_string::<R>(val, reader, expected_indent_level)?;

        Ok(Some(UObjectProperty {
            header: UObjectPropertyHeader {
                name,
                arr_index,
                r#type: data.get_string_type().to_owned(),
            },
            metadata,
            data
        }))
    }
}

#[derive(PartialEq, Debug)]
pub enum UObjectPropertyMetadata {
    Array(String),
    Bool(bool),
    Byte(u64,u8),
    Enum(String),
    Map(String, String),
    Struct(Vec<u8>),
    None,
}

impl UObjectPropertyMetadata {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(reader: &mut R, r#type: &str, name_map: &[String]) -> Self {
        match r#type {
            "ArrayProperty" => {
                let item_type = reader.read_u64::<E>().unwrap() as usize;
                let item_type = &name_map[item_type];

                let _unknown_byte = reader.read_u8().unwrap();
                UObjectPropertyMetadata::Array(item_type.clone())
            },
            "BoolProperty" => {
                let val = reader.read_u8().unwrap() > 0;
                let _unknown_byte = reader.read_u8().unwrap();
                UObjectPropertyMetadata::Bool(val)
            },
            "ByteProperty" => {
                let enum_name = reader.read_u64::<E>().unwrap();
                let val = reader.read_u8().unwrap();
                UObjectPropertyMetadata::Byte(enum_name, val)
            },
            "EnumProperty" => {
                let enum_name = reader.read_u64::<E>().unwrap() as usize;
                let _unknown_byte = reader.read_u8().unwrap();
                UObjectPropertyMetadata::Enum(name_map[enum_name].clone())
            },
            "StructProperty" => {
                let mut data = vec![0;25];
                reader.read_exact(&mut data).unwrap();
                UObjectPropertyMetadata::Struct(data)
            },
            "MapProperty" => {
                let key_type = reader.read_u64::<E>().unwrap() as usize;
                let key_type = &name_map[key_type];

                let value_type = reader.read_u64::<E>().unwrap() as usize;
                let value_type = &name_map[value_type];

                let _unknown_byte = reader.read_u8().unwrap();
                let _unknown_value = reader.read_u32::<E>().unwrap() as usize;

                UObjectPropertyMetadata::Map(key_type.clone(), value_type.clone())
            },
            _ => {
                let _unknown_byte = reader.read_u8().unwrap();
                UObjectPropertyMetadata::None
            }
        }
    }

    pub fn to_bytes<W: Write, E: byteorder::ByteOrder>(&self, writer: &mut W, name_map: &[String]) -> usize {
        match self {
            Self::Array(item_type) => {
                let item_type_index = name_map.iter().position(|n| n == item_type).unwrap_or_else(|| panic!("Object type [{}] wasn't in name map", item_type)) as u64;
                writer.write_u64::<E>(item_type_index).unwrap();
                writer.write_u8(0).unwrap();
                8 + 1
            },
            Self::Bool(val) => {
                if *val {
                    writer.write_u8(1).unwrap(); // true
                } else {
                    writer.write_u8(0).unwrap(); // false
                }
                writer.write_u8(0).unwrap();  // Unknown value - seems to be 0?

                2
            }
            Self::Byte(enum_name, val, ) => {
                writer.write_u64::<E>(*enum_name).unwrap();
                writer.write_u8(*val).unwrap();
                8 + 1
            },
            Self::Enum(enum_name) => {
                writer.write_u64::<E>(name_map.iter().position(|n| n == enum_name).unwrap_or_else(|| panic!("Object type [{enum_name}] wasn't in name map")) as u64).unwrap();
                writer.write_u8(0).unwrap();
                8 + 1
            },
            Self::Map(key_type, val_type) => {
                let key_type_index = name_map.iter().position(|n| n == key_type).unwrap_or_else(|| panic!("Object type [{}] wasn't in name map", key_type)) as u64;
                let val_type_index = name_map.iter().position(|n| n == val_type).unwrap_or_else(|| panic!("Object type [{}] wasn't in name map", val_type)) as u64;

                writer.write_u64::<E>(key_type_index).unwrap();
                writer.write_u64::<E>(val_type_index).unwrap();
                writer.write_u8(0).unwrap();  // Unknown value - seems to be 0?
                writer.write_u32::<E>(0).unwrap();   // Unknown value - seems to be 0?
                8 + 8 + 1 + 4
            },
            Self::Struct(data) => {
                writer.write_all(data).unwrap();
                data.len()
            },
            Self::None => {
                writer.write_u8(0).unwrap();  // Unknown value - seems to be 0?
                1
            }
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum UObjectPropertyData {
    Array(Vec<UObjectPropertyData>, Option<(UObjectPropertyHeader, String)>),
    Bool,
    Byte(u8),
    Enum(String),
    Struct(Vec<UObjectProperty>, Vec<u8>),
    Float(f32),
    String(String),
    StringUtf16(String),
    Map(Vec<(UObjectPropertyData, UObjectPropertyData)>),
    Name(String),
    UInt16(u16),
    UInt32(u32),
    Int8(i8),
    Int16(i16),
    Int32(i32),
}

impl UObjectPropertyData {
    pub fn get_string_type(&self) -> &str {
        match self {
            UObjectPropertyData::Array(_, _) => "ArrayProperty",
            UObjectPropertyData::Bool => "BoolProperty",
            UObjectPropertyData::Byte(_) => "ByteProperty",
            UObjectPropertyData::Enum(_) => "EnumProperty",
            UObjectPropertyData::Struct(_,_) => "StructProperty",
            UObjectPropertyData::Float(_) => "FloatProperty",
            UObjectPropertyData::String(_) => "StrProperty",
            UObjectPropertyData::StringUtf16(_) => "StrProperty",
            UObjectPropertyData::Map(_) => "MapProperty",
            UObjectPropertyData::Name(_) => "NameProperty",
            UObjectPropertyData::UInt16(_) => "UInt16Property",
            UObjectPropertyData::UInt32(_) => "UInt32Property",
            UObjectPropertyData::Int8(_) => "Int8Property",
            UObjectPropertyData::Int16(_) => "Int16Property",
            UObjectPropertyData::Int32(_) => "IntProperty",
        }
    }

    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(reader: &mut R, r#type: &str, metadata: &UObjectPropertyMetadata, name_map: &[String], expected_size: usize) -> Result<Self, Box<dyn Error>> {
        match r#type {
            "ArrayProperty" => {
                let len = reader.read_u32::<E>().unwrap() as usize;
                let mut items = Vec::with_capacity(len);

                let item_type = match metadata {
                    UObjectPropertyMetadata::Array(v) => v,
                    _ => panic!("ArrayProperty should always have Array metadata!")
                };

                let struct_meta = if item_type == "StructProperty" {
                    let item_schema = UObjectPropertyHeader::from_buffer::<R,E>(reader, name_map).expect("Array property missing item definition!");
                    let array_name = name_map[reader.read_u64::<E>().unwrap() as usize].clone();
                    let mut _additional_unknown_data = vec![0;17];
                    reader.read_exact(&mut _additional_unknown_data).unwrap();
                    assert!(vec![0;17].eq(&_additional_unknown_data), "Array of struct metadata wasn't empty!");
                    Some((item_schema.0, array_name))
                } else {
                    None
                };
                
                for _ in 0..len {
                    items.push(UObjectPropertyData::from_buffer::<_,E>(reader, item_type, metadata, name_map, expected_size)?);
                }
                Ok(UObjectPropertyData::Array(items, struct_meta))
            },
            "BoolProperty" => {
                Ok(UObjectPropertyData::Bool)
            },
            "ByteProperty" => {
                let val = reader.read_u8().unwrap();
                Ok(UObjectPropertyData::Byte(val))
            },
            "EnumProperty" => {
                Ok(UObjectPropertyData::Enum(name_map[reader.read_u64::<E>().unwrap() as usize].clone()))
            },
            "StructProperty" => {
                //HACK - dunno how to handle struct data that doesn't look like regular properties
                let next_name = reader.read_u64::<E>().unwrap();
                reader.seek(SeekFrom::Current(-8)).unwrap();
                if next_name == 0 || next_name >= name_map.len() as u64 {
                    let mut additional_data = vec![0;expected_size];
                    reader.read_exact(&mut additional_data).unwrap();
                    return Ok(UObjectPropertyData::Struct(vec![], additional_data));
                }

                let mut props = vec![];
                while let Some(prop) = UObjectProperty::from_buffer::<R,E>(reader, name_map)? {
                    props.push(prop);
                }
                Ok(UObjectPropertyData::Struct(props, vec![]))
            },
            "FloatProperty" => {
                let val = reader.read_f32::<E>().unwrap();
                Ok(UObjectPropertyData::Float(val))
            },
            "StrProperty" => {
                let len = reader.read_i32::<E>().unwrap();
                match len.cmp(&0) {
                    Ordering::Less => {
                        let len = -len as usize;
                        let mut raw_string = Vec::with_capacity(len-1);
                        for _ in 0..len-1 {
                            raw_string.push(reader.read_u16::<E>().unwrap());
                        }
                        if reader.read_u16::<E>().unwrap() != 0 {
                            Err(format!("Malformed FString at byte 0x{:x} - length or termination byte is incorrect", reader.stream_position().unwrap()))?;
                        }
                        Ok(UObjectPropertyData::StringUtf16(String::from_utf16(&raw_string).unwrap()))
                    },
                    Ordering::Greater => {
                        let len = len as usize;
                        let mut raw_string = vec![0;len-1];
                        reader.read_exact(&mut raw_string).unwrap();
                        if reader.read_u8().unwrap() != 0 {
                            Err(format!("Malformed FString at byte 0x{:x} - length or termination byte is incorrect", reader.stream_position().unwrap()))?;
                        }
                        Ok(UObjectPropertyData::String(String::from_utf8(raw_string).unwrap()))
                    },
                    Ordering::Equal => {
                        Ok(UObjectPropertyData::String(String::new()))

                    }
                }
            },
            "MapProperty" => {
                let (key_type, value_type) = match metadata {
                    UObjectPropertyMetadata::Map(key_type, value_type) => (key_type, value_type),
                    _ => panic!("MapProperty should always have UObjectPropertyMetadata::Map present!"),
                };

                let arr_size = reader.read_u32::<E>().unwrap() as usize;
                let mut sets = Vec::with_capacity(arr_size);
                for _ in 0..arr_size {
                    let next_key = UObjectPropertyData::from_buffer::<R,E>(reader, key_type, metadata, name_map, expected_size)?;
                    let next_value = UObjectPropertyData::from_buffer::<R,E>(reader, value_type, metadata, name_map, expected_size)?;
                    sets.push((next_key, next_value));
                }

                Ok(UObjectPropertyData::Map(sets))
            },
            "NameProperty" => {
                Ok(UObjectPropertyData::Name(name_map[reader.read_u64::<E>().unwrap() as usize].clone()))
            },
            "UInt16Property" => {
                Ok(UObjectPropertyData::UInt16(reader.read_u16::<E>().unwrap()))
            },
            "UInt32Property" => {
                Ok(UObjectPropertyData::UInt32(reader.read_u32::<E>().unwrap()))
            },
            "Int8Property" => {
                Ok(UObjectPropertyData::Int8(reader.read_i8().unwrap()))
            },
            "Int16Property" => {
                Ok(UObjectPropertyData::Int16(reader.read_i16::<E>().unwrap()))
            },
            "IntProperty" => {
                Ok(UObjectPropertyData::Int32(reader.read_i32::<E>().unwrap()))
            },
            _ => {
                //Err(format!("Unhandled property type: {}", r#type))?
                eprintln!("WARNING: Unhandled property type: {}  # Expect errors.", r#type);
                
                let mut additional_data = vec![0;expected_size];
                reader.read_exact(&mut additional_data).unwrap();
                Ok(UObjectPropertyData::Struct(vec![], additional_data))
            }
        }
    }

    pub fn to_bytes<W: Write, E: byteorder::ByteOrder>(&self, writer: &mut W, name_map: &[String]) -> usize {
        match self {
            Self::Array(items, struct_meta) => {
                writer.write_u32::<E>(items.len() as u32).unwrap();
                let mut written_len = 4;

                let mut data = Cursor::new(vec![]);
                for i in items {
                    i.to_bytes::<Cursor<Vec<u8>>,E>(&mut data, name_map);
                }
                let data = data.into_inner();

                if let Some((item_schema, array_name)) = struct_meta {
                    item_schema.to_bytes::<W,E>(writer, name_map, data.len());
                    written_len += UObjectPropertyHeader::byte_len();
                    let array_name_index = name_map.iter().position(|n| n == array_name).unwrap_or_else(|| panic!("Object type [{}] wasn't in name map", array_name)) as u64;
                    writer.write_u64::<E>(array_name_index).unwrap();
                    written_len += 8;
                    let additional_unknown_data = [0u8;17];
                    writer.write_all(&additional_unknown_data).unwrap();
                    written_len += 17;
                }

                writer.write_all(&data).unwrap(); // len += data.len()
                written_len += data.len();
                
                written_len
            },
            Self::Bool => {
                0 
            },
            Self::Byte(val, ) => {
                writer.write_u8(*val).unwrap();
                1
            },
            Self::Enum(enum_val) => {
                writer.write_u64::<E>(name_map.iter().position(|n| n == enum_val).unwrap_or_else(|| panic!("Object type [{enum_val}] wasn't in name map")) as u64).unwrap();
                8
            },
            Self::Struct(val, raw) => {
                let mut len = 0;
                if !val.is_empty() {
                    for v in val {
                        len += v.to_bytes::<W,E>(writer, name_map);
                    }
                    let none_index = name_map.iter().position(|n| n == "None").unwrap_or_else(|| panic!("Object type [None] wasn't in name map")) as u64;
                    writer.write_u64::<E>(none_index).unwrap();
                    len += std::mem::size_of::<u64>();
                } else {
                    writer.write_all(raw).unwrap();
                    len += raw.len();
                }
                len
            },
            Self::Float(val) => {
                writer.write_f32::<E>(*val).unwrap();
                4
            },
            Self::String(val) => {
                let len = if val.is_empty() {
                    writer.write_u32::<E>(0).unwrap();
                    0
                } else {
                    let len = val.len() + 1; // +1 for termination byte
                    writer.write_u32::<E>(len as u32).unwrap();
                    writer.write_all(val.as_bytes()).unwrap();
                    writer.write_u8(0).unwrap();  // FString termination byte
                    len
                };
                
                4 + len
            },
            Self::StringUtf16(val) => {
                let bytes: Vec<u16> = val.encode_utf16().collect();
                let len = bytes.len() + 1;
                writer.write_i32::<E>(-(len as i32)).unwrap();
                for char in bytes {
                    writer.write_u16::<E>(char).unwrap();
                }
                writer.write_u16::<E>(0).unwrap();  // FString termination byte
                
                4 + (len * 2)
            },
            Self::Map(val) => {
                writer.write_u32::<E>(val.len() as u32).unwrap();
                let mut size = 8; // Seems like final size is 8 + map data size...?
                for v in val {
                    size += v.0.to_bytes::<W,E>(writer, name_map);
                    size += v.1.to_bytes::<W,E>(writer, name_map);
                }

                size
            },
            Self::Name(val) => {
                writer.write_u64::<E>(name_map.iter().position(|n| n == val).unwrap_or_else(|| panic!("Object type [{val}] wasn't in name map")) as u64).unwrap();
                8
            }
            Self::UInt16(val) => {
                writer.write_u16::<E>(*val).unwrap();
                2
            },
            Self::UInt32(val) => {
                writer.write_u32::<E>(*val).unwrap();
                4
            },
            Self::Int8(val) => {
                writer.write_i8(*val).unwrap();
                1
            },
            Self::Int16(val) => {
                writer.write_i16::<E>(*val).unwrap();
                2
            },
            Self::Int32(val) => {
                writer.write_i32::<E>(*val).unwrap();
                4
            },
        }
    }

    pub fn to_string<W: Write>(&self, metadata: &UObjectPropertyMetadata, writer: &mut W, indent_spaces: usize) {
        match self {
            Self::Array(items, struct_meta) => {
                let item_type = match metadata {
                    UObjectPropertyMetadata::Array(i) => i,
                    _ => panic!("Array property data must have array metadata")
                };

                writer.write_all("!Array\n".as_bytes()).unwrap();
                writer.write_all(format!("{}item_type: {item_type}\n", " ".repeat(indent_spaces + 2)).as_bytes()).unwrap();
                if let Some((header, array_name)) = struct_meta {
                    writer.write_all(format!("{}item_schema:\n", " ".repeat(indent_spaces + 2)).as_bytes()).unwrap();
                    writer.write_all(format!("{}  name: {}\n", " ".repeat(indent_spaces + 2), header.name).as_bytes()).unwrap();
                    writer.write_all(format!("{}  type: {}\n", " ".repeat(indent_spaces + 2), header.r#type).as_bytes()).unwrap();
                    writer.write_all(format!("{}array_name: {array_name}\n", " ".repeat(indent_spaces + 2)).as_bytes()).unwrap();
                }

                writer.write_all(format!("{}items:\n", " ".repeat(indent_spaces + 2)).as_bytes()).unwrap();
                for (i, item) in items.iter().enumerate() {
                    writer.write_all(format!("{}- {}:", " ".repeat(indent_spaces + 2), i).as_bytes()).unwrap();
                    item.to_string(metadata, writer, indent_spaces + 4);
                }
            },
            Self::Bool => {
                let val = match metadata {
                    UObjectPropertyMetadata::Bool(val) => val,
                    _ => panic!("Bool property data must have bool metadata")  
                };
                if *val {
                    writer.write_all("true\n".as_bytes()).unwrap();
                } else {
                    writer.write_all("false\n".as_bytes()).unwrap();
                }
            },
            Self::Byte(val) => {
                let (enum_name, metadata_val) = match metadata {
                    UObjectPropertyMetadata::Byte(e,m) => (e,m),
                    UObjectPropertyMetadata::Array(_) => (&0, &0), // Bytes seem to be able to be in arrays without needing metadata
                    _ => panic!("Byte property data must have byte metadata")
                };
                writer.write_all(format!("!ByteProperty {enum_name:x} {metadata_val:x} {val:x}\n").as_bytes()).unwrap();
            },
            Self::Enum(enum_val) => {
                let enum_name = match metadata {
                    UObjectPropertyMetadata::Enum(v) => v,
                    _ => panic!("Enum property data must have enum metadata")
                };
                let sanitized_val = enum_val.replace("::", "->");
                writer.write_all(format!("!EnumProperty {enum_name} {sanitized_val}\n").as_bytes()).unwrap();
            },
            Self::Struct(val, raw) => {
                if let UObjectPropertyMetadata::Struct(data) = metadata {
                    writer.write_all(format!("!struct {} {}", BASE64_STANDARD.encode(data), BASE64_STANDARD.encode(raw)).as_bytes()).unwrap();
                }
                writer.write_all("\n".as_bytes()).unwrap();
                for v in val {
                    writer.write_all(" ".repeat(indent_spaces + 2).as_bytes()).unwrap();
                    v.to_string::<W>(writer, indent_spaces + 2);
                }
            },
            Self::Float(val) => {
                writer.write_all(format!("{val}\n").as_bytes()).unwrap();
            },
            Self::String(val) => {
                if val.is_empty() {
                    writer.write_all("!EmptyString\n".as_bytes()).unwrap();
                } else {
                    let val = val.replace('\n', "\\n");
                    writer.write_all(format!("\"{val}\"\n").as_bytes()).unwrap();
                }
            },
            Self::StringUtf16(val) => {
                let val = val.replace('\n', "\\n");
                writer.write_all(format!("!utf16 {val}\n").as_bytes()).unwrap();
            },
            Self::Map(val) => {
                writer.write_all("!Map\n".as_bytes()).unwrap();

                let (key_type, val_type) = match metadata {
                    UObjectPropertyMetadata::Map(k,v) => (k,v),
                    _ => panic!("Map property data must have map metadata")
                };
                let indention = " ".repeat(indent_spaces + 2);
                writer.write_all(format!("{}key_type: {key_type}\n", indention).as_bytes()).unwrap();
                writer.write_all(format!("{}val_type: {val_type}\n", indention).as_bytes()).unwrap();
                writer.write_all(format!("{}map_data:\n", indention).as_bytes()).unwrap();

                for v in val {
                    let key_string = match &v.0 {
                        Self::Enum(v) => v.replace("::", "->"),
                        Self::Int32(v) => v.to_string(),
                        Self::UInt16(v) => v.to_string(),
                        Self::String(v) => v.clone(),
                        Self::Float(v) => format!("{v}"),
                        Self::Byte(v) => format!("{v:x}"),
                        _ => panic!("Unprintable map key type: {key_type}")
                    };
                    writer.write_all(format!("{}- {}:", " ".repeat(indent_spaces + 4), key_string).as_bytes()).unwrap();
                    v.1.to_string::<W>(metadata,writer, indent_spaces + 6);
                }
            },
            Self::Name(val) => {
                writer.write_all(format!("!name {val}\n").as_bytes()).unwrap();
            },
            Self::UInt16(val) => {
                writer.write_all(format!("!u16 {val}\n").as_bytes()).unwrap();
            },
            Self::UInt32(val) => {
                writer.write_all(format!("!u32 {val}\n").as_bytes()).unwrap();
            },
            Self::Int8(val) => {
                writer.write_all(format!("!i8 {val}\n").as_bytes()).unwrap();
            },
            Self::Int16(val) => {
                writer.write_all(format!("!i16 {val}\n").as_bytes()).unwrap();
            },
            Self::Int32(val) => {
                writer.write_all(format!("!i32 {val}\n").as_bytes()).unwrap();
            },
        }
    }

    pub fn from_string<R: BufRead + Seek>(val: &str, reader: &mut R, expected_indent_level: usize) -> Result<(Self, UObjectPropertyMetadata), Box<dyn Error>> {
        let val = val.trim();
        if val.is_empty() || val.starts_with("!struct") { // Struct start
            let (meta, raw) = if val.is_empty() {
                (UObjectPropertyMetadata::None, vec![])
            } else {
                let mut vals = val.split_whitespace();
                vals.next().unwrap(); // !struct

                let err = format!("Error at 0x{:x}: !struct should have one or two base64 parameters", reader.stream_position().unwrap());
                let meta = BASE64_STANDARD.decode(vals.next().ok_or(err.clone())?).map_err(|_| "Unable to read !struct metadata from base64 string. This value shouldn't be manually edited.".to_string())?;
                let raw = vals.next().map(|v| BASE64_STANDARD.decode(v).map_err(|_| "Unable to read !struct metadata from base64 string. This value shouldn't be manually edited.".to_string())).transpose()?.unwrap_or(vec![]);
                (UObjectPropertyMetadata::Struct(meta), raw)
            };

            let mut props = vec![];
            while let Some(prop) = UObjectProperty::from_string::<R>(reader, expected_indent_level + 2)? {
                props.push(prop);
            }
            Ok((UObjectPropertyData::Struct(props, raw), meta))
        } else if val.starts_with("!Map") {
            let start_position = reader.stream_position().unwrap();
            let mut key_type:   Option<String> = None;
            let mut value_type: Option<String> = None;
            let mut sets = vec![];

            for _ in 0..3 {
                let next_line = next_nonempty_line(reader);
                if !check_indent(&next_line, expected_indent_level + 2) {
                    Err(format!("Map at 0x{start_position:x} should have properties (in order): key_type, val_type, map_data"))?;
                }

                let (key, val) = next_line.split_once(':').ok_or(format!("Map at 0x{:x} - expected [key_type:] property, but got:\n{}", start_position, next_line.trim()))?;
                match key.trim() {
                    "key_type" => { key_type = Some(val.trim().to_owned()); },
                    "val_type" => { value_type = Some(val.trim().to_owned()); },
                    "map_data" => {
                        if key_type.is_none() {
                            Err(format!("Map at 0x{start_position:x} - key_type should come before map_data"))?;
                        }
                        if value_type.is_none() {
                            Err(format!("Map at 0x{start_position:x} - val_type should come before map_data"))?;
                        }

                        let format_err = format!("Map at 0x{start_position:x} - map_data should use format ' - key: value'");
                        loop {
                            let next_line = next_nonempty_line(reader);
                            if !next_line.trim().starts_with('-') || !check_indent(&next_line, expected_indent_level + 4) {
                                reader.seek(SeekFrom::Current(-(next_line.len() as i64))).unwrap();
                                break;
                            }
    
                            let (key, val) = next_line.split_once('-').ok_or(format_err.clone())?.1.split_once(':').ok_or(format_err.clone())?;
                            let key = key.trim();
                            let key = match key_type.as_ref().unwrap().as_str() {
                                "IntProperty" => UObjectPropertyData::Int32(key.parse()?),
                                "UInt16Property" => UObjectPropertyData::UInt16(key.parse()?),
                                "StrProperty" => UObjectPropertyData::String(key.to_owned()),
                                "FloatProperty" => UObjectPropertyData::Float(key.parse()?),
                                "ByteProperty" => UObjectPropertyData::Byte(u8::from_str_radix(key, 16)?),
                                "EnumProperty" => UObjectPropertyData::Enum(key.replace("->", "::")),
                                other => Err(format!("Map at 0x{start_position:x} - unable to read data of key type '{other}'"))?,
                            };
                            let val = UObjectPropertyData::from_string::<R>(val, reader, expected_indent_level + 6)?;
                            sets.push((key, val));
                        }

                        let val_type = value_type.as_ref().unwrap().as_str();
                        for (_key, (item, _meta)) in &sets {
                            let set_val_type = item.get_string_type();
                            if set_val_type != val_type {
                                Err(format!("Map at 0x{start_position:x} - expected value type '{val_type}', but got '{set_val_type}'"))?;
                            }
                        }
                    }
                    _ => { Err(format!("Map at 0x{:x} - expected key_type or val_type, but got {}", start_position, key.trim()))?; }
                }
            }

            if sets.is_empty() {
                Err(format!("Map at 0x{start_position:x} - missing map_data!"))?;
            }

            Ok((
                UObjectPropertyData::Map(sets.into_iter().map(|s| (s.0, s.1.0)).collect()),
                UObjectPropertyMetadata::Map(
                    key_type.ok_or(format!("Map at 0x{start_position:x} - missing key_type!"))?,
                    value_type.ok_or(format!("Map at 0x{start_position:x} - missing val_type!"))?
                )
            ))

        } else if val.starts_with("!Array") {
            let start_position = reader.stream_position().unwrap();
            let mut item_type:   Option<String> = None;
            let mut item_schema: Option<UObjectPropertyHeader> = None;
            let mut array_name:  Option<String> = None;
            let mut items = vec![];

            let mut i = 0;
            while i < 2 {
                let next_line = next_nonempty_line(reader);
                if !check_indent(&next_line, expected_indent_level + 2) {
                    Err(format!("Array at 0x{start_position:x} should have properties (in order): item_type, <item_schema?>, <array_name?>, items"))?;
                }

                let (key, val) = next_line.split_once(':').ok_or(format!("Array at 0x{:x} - expected [item_type:] property, but got:\n{}", start_position, next_line.trim()))?;
                match key.trim() {
                    "item_type" => { 
                        item_type = Some(val.trim().to_owned());
                        if val.trim() == "StructProperty" {
                            i -= 2;
                        }
                    },
                    "item_schema" => { 
                        let mut name:   Option<String> = None;
                        let mut r#type: Option<String> = None;
                        for _ in 0..2 {
                            let next_line = next_nonempty_line(reader);
                            if !check_indent(&next_line, expected_indent_level + 4) {
                                Err(format!("Array at 0x{start_position:x} - item_schema should have properties (in order): name, type"))?;
                            }
                            let (key, val) = next_line.split_once(':').ok_or(format!("Array at 0x{start_position:x} - misformatted item_schema property"))?;
                            match key.trim() {
                                "name" => { name = Some(val.trim().to_string()); },
                                "type" => { r#type = Some(val.trim().to_string()); },
                                _ => Err(format!("Array at 0x{start_position:x}, item_schema: unknown property [{}]", val.trim()))?
                            }
                        }
                        item_schema = Some(UObjectPropertyHeader {
                            name: name.ok_or(format!("Array at 0x{start_position:x} - item_schema missing 'name' property!"))?,
                            r#type: r#type.ok_or(format!("Array at 0x{start_position:x} - item_schema missing 'type' property!"))?,
                            arr_index: 0
                        }); 
                    },
                    "array_name" => { array_name = Some(val.trim().to_owned()); },
                    "items" => {
                        if item_type.is_none() {
                            Err(format!("Array at 0x{start_position:x} - item_type should come before items"))?;
                        }

                        let format_err = format!("Array at 0x{start_position:x} - items should use format ' - <index>: value'");
                        loop {
                            let next_line = next_nonempty_line(reader);
                            if !next_line.trim().starts_with('-') || !check_indent(&next_line, expected_indent_level + 2) {
                                reader.seek(SeekFrom::Current(-(next_line.len() as i64))).unwrap();
                                break;
                            }
    
                            let (_, val) = next_line.split_once(':').ok_or(format_err.clone())?;
                            let val = UObjectPropertyData::from_string::<R>(val, reader, expected_indent_level + 4)?;
                            items.push(val);
                        }

                        let val_type = item_type.as_ref().unwrap().as_str();
                        for (item, _meta) in &items {
                            let entry_type = item.get_string_type();
                            if entry_type != val_type {
                                Err(format!("Array at 0x{start_position:x} - expected item type '{val_type}', but got '{entry_type}'"))?;
                            }
                        }
                    }
                    _ => { Err(format!("Array at 0x{:x} - expected item_type, item_schema, or items, but got {}", start_position, key.trim()))?; }
                }
                i += 1;
            }

            if items.is_empty() {
                println!("Info: Array at 0x{start_position:x} - missing items!");
            }

            Ok((
                UObjectPropertyData::Array(
                    items.into_iter().map(|i| i.0).collect(),
                    item_schema.map(|s| (s, array_name.unwrap_or_else(|| panic!("Array at 0x{start_position:x} - missing array_name!")))),
                ),
                UObjectPropertyMetadata::Array(item_type.ok_or(format!("Array at 0x{start_position:x} - missing item_type!"))?)
            ))
        } else if val.starts_with("!u16") {
            let (_, u16value) = val.split_once(' ').ok_or(format!("Error at 0x{:x}: !u16 should have one integer parameter", reader.stream_position().unwrap()))?;
            Ok((UObjectPropertyData::UInt16(u16value.parse::<u16>()?), UObjectPropertyMetadata::None))
        } else if val.starts_with("!u32") {
            let (_, u32value) = val.split_once(' ').ok_or(format!("Error at 0x{:x}: !u32 should have one integer parameter", reader.stream_position().unwrap()))?;
            Ok((UObjectPropertyData::UInt32(u32value.parse::<u32>()?), UObjectPropertyMetadata::None))
        } else if val.starts_with("!i8") {
            let (_, i8value) = val.split_once(' ').ok_or(format!("Error at 0x{:x}: !i8 should have one integer parameter", reader.stream_position().unwrap()))?;
            Ok((UObjectPropertyData::Int8(i8value.parse::<i8>()?), UObjectPropertyMetadata::None))
        } else if val.starts_with("!i16") {
            let (_, i16value) = val.split_once(' ').ok_or(format!("Error at 0x{:x}: !i16 should have one integer parameter", reader.stream_position().unwrap()))?;
            Ok((UObjectPropertyData::Int16(i16value.parse::<i16>()?), UObjectPropertyMetadata::None))
        } else if val.starts_with("!i32") {
            let (_, i32value) = val.split_once(' ').ok_or(format!("Error at 0x{:x}: !i32 should have one integer parameter", reader.stream_position().unwrap()))?;
            Ok((UObjectPropertyData::Int32(i32value.parse::<i32>()?), UObjectPropertyMetadata::None))
        } else if val.starts_with("!ByteProperty") {
            let mut vals = val.split_whitespace();
            vals.next().unwrap(); // !ByteProperty

            let err = format!("Error at 0x{:x}: !ByteProperty should have three hex parameters", reader.stream_position().unwrap());
            let enum_id = vals.next().ok_or(err.clone())?;
            let enum_val = vals.next().ok_or(err.clone())?;
            let byte_val = vals.next().ok_or(err)?;
            
            Ok((UObjectPropertyData::Byte(u8::from_str_radix(byte_val, 16)?), UObjectPropertyMetadata::Byte(u64::from_str_radix(enum_id, 16)?, u8::from_str_radix(enum_val, 16)?)))
        } else if val.starts_with("!EnumProperty") {
            let mut vals = val.split_whitespace();
            vals.next().unwrap(); // !EnumProperty

            let err = format!("Error at 0x{:x}: !EnumProperty should have two string parameters", reader.stream_position().unwrap());
            let enum_name = vals.next().ok_or(err.clone())?;
            let enum_val = vals.next().ok_or(err.clone())?;
            
            Ok((UObjectPropertyData::Enum(enum_val.replace("->", "::")), UObjectPropertyMetadata::Enum(enum_name.to_owned())))
        } else if val.starts_with("!utf16") {
            let (_, utf16val) = val.split_once(' ').ok_or(format!("Error at 0x{:x}: !utf16 should have one string parameter", reader.stream_position().unwrap()))?;
            Ok((UObjectPropertyData::StringUtf16(utf16val.replace("\\n", "\n")), UObjectPropertyMetadata::None))
        } else if val.starts_with("!EmptyString") {
            Ok((UObjectPropertyData::String(String::new()), UObjectPropertyMetadata::None))
        } else if val.starts_with("!name") {
            let (_, name) = val.split_once(' ').ok_or(format!("Error at 0x{:x}: !name should have one string parameter", reader.stream_position().unwrap()))?;
            Ok((UObjectPropertyData::Name(name.to_owned()), UObjectPropertyMetadata::None))
        } else if let Ok(val) = val.parse::<f32>() {
            Ok((UObjectPropertyData::Float(val), UObjectPropertyMetadata::None))
        } else if let Ok(val) = val.parse::<bool>() {
            Ok((UObjectPropertyData::Bool, UObjectPropertyMetadata::Bool(val)))
        } else {
            let str: String = if val.starts_with('\"') {
                if !val.ends_with('\"') { Err(format!("String value [{val}] doesn't have closing quote"))? }
                val.chars().skip(1).take(val.len()-2).collect()
            } else { 
                val.chars().collect()
            };
            Ok((UObjectPropertyData::String(str.replace("\\n", "\n")), UObjectPropertyMetadata::None))
        }
    }
}

fn check_indent(val: &str, spaces: usize) -> bool {
    val.replace('\t', "  ").chars().take(spaces).all(|c| c == ' ')
}

/// 
/// Returns the next non-empty line in the reader.  If an empty line is returned, the reader has reached EOF.
/// 
fn next_nonempty_line<R: BufRead + Seek>(reader: &mut R) -> String {
    let mut line = String::new();
    while line.trim().is_empty() {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
    }
    line
}

pub struct IoUObject {
    summary: UObjectSummary,
    properties: Vec<UObjectProperty>,
}

impl IoUObject {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let summary = UObjectSummary::from_buffer::<R,E>(reader)?;
        let mut properties = vec![];
        while let Some(prop) = UObjectProperty::from_buffer::<R,E>(reader, &summary.name_map)? {
            properties.push(prop);
        }

        Ok(Self {
            summary,
            properties,
        })
    }

    pub fn to_bytes<W: Write, E: byteorder::ByteOrder>(&self, writer: &mut W) -> usize {
        let mut properties_bytes = vec![];
        for prop in &self.properties {
            prop.to_bytes::<_,E>(&mut properties_bytes, &self.summary.name_map);
        }
        let none_index = self.summary.name_map.iter().position(|n| n == "None").unwrap_or_else(|| panic!("Object type [None] wasn't in name map")) as u64;
        properties_bytes.write_u64::<E>(none_index).unwrap();

        let summary_bytes = self.summary.to_bytes::<E>();
        writer.write_all(&summary_bytes).unwrap();
        writer.write_all(&properties_bytes).unwrap();
        writer.write_all(&[0;4]).unwrap();

        summary_bytes.len() + properties_bytes.len() + 4
    }

    pub fn to_string<W: Write>(&self, writer: &mut W) {
        writer.write_all(format!("summary: {}\n", self.summary).as_bytes()).unwrap();
        writer.write_all("contents:\n".as_bytes()).unwrap();

        for prop in &self.properties {
            let indent_spaces = 2usize;
            writer.write_all("  ".as_bytes()).unwrap();
            prop.to_string(writer, indent_spaces);
        }
    }

    pub fn from_string<R: BufRead + Seek>(reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        if !line.starts_with("summary:") {
            Err("IoUObject string should start with 'summary:' property!")?;
        }

        let (_, summary) = line.split_once(':').ok_or("Missing summary value")?;
        let summary = UObjectSummary::from_string(summary.trim())?;

        line.clear();
        reader.read_line(&mut line).unwrap();

        if !line.starts_with("contents:") {
            Err("IoUObject string should follow 'summary:' with 'contents:'")?;
        }

        let mut properties = vec![];
        while let Some(prop) = UObjectProperty::from_string::<R>(reader, 2)? {
            properties.push(prop);
        }

        Ok(Self {
            summary,
            properties,
        })
    }
}

#[allow(dead_code)]
#[allow(unused_imports)]
mod test {
    use byteorder::LE;
    use std::io::{Cursor, Write};

    use super::{IoUObject, StringType, UObjectProperty, UObjectPropertyData, UObjectPropertyHeader, UObjectPropertyMetadata, UObjectSummary, UObjectSummaryHeader};

    fn get_test_object_summary() -> UObjectSummary {
        let summary_header = UObjectSummaryHeader {
            name: 1,
            source_name: 5,
            package_flags: 0,
            cooked_header_size: 0x40,
            name_map_names_offset: 0x40,
            name_map_names_size: 0x10,
            name_map_hashes_offset: 0x50,
            name_map_hashes_size: 0x98,
            import_map_offset: 0x130,
            export_bundles_offset: 0x140,
            export_map_offset: 0x150,
            graph_data_offset: 0x12c,
            graph_data_size: 0x04,
            pad: 0
        };
        UObjectSummary {
            header: summary_header,
            name_map: vec![
                "None".to_string(),
                "ArrayProperty".to_string(),
                "TestArray".to_string(),
                "BoolProperty".to_string(),
                "TestBool".to_string(),
                "ByteProperty".to_string(),
                "TestByte".to_string(),
                "IntProperty".to_string(),
                "TestInt".to_string(),
                "FloatProperty".to_string(),
                "TestFloat".to_string(),
                "MapProperty".to_string(),
                "TestMap".to_string(),
                "StrProperty".to_string(),
                "TestString".to_string(),
                "StructProperty".to_string(),
                "TestStruct".to_string(),
                "SomeUtf16Property".to_string(),
            ],
            name_map_type: vec![
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf8,
                StringType::Utf16,
            ],
            remaining_bytes: vec![0;0]
        }
    }

    fn mkbool(value: bool) -> UObjectProperty {
        let data = UObjectPropertyData::Bool;
        UObjectProperty {
            header: UObjectPropertyHeader {
                name: "TestBool".to_string(),
                arr_index: 0,
                r#type: data.get_string_type().to_owned(),
            },
            metadata: UObjectPropertyMetadata::Bool(value),
            data
        }
    }

    fn mkbyte(enum_type: u64, value: u8) -> UObjectProperty {
        let data = UObjectPropertyData::Byte(value);
        UObjectProperty {
            header: UObjectPropertyHeader {
                name: "TestByte".to_string(),
                arr_index: 0,
                r#type: data.get_string_type().to_owned(),
            },
            metadata: UObjectPropertyMetadata::Byte(enum_type, 0),
            data
        }
    }

    fn mkint(value: i32) -> UObjectProperty {
        let data = UObjectPropertyData::Int32(value);
        UObjectProperty {
            header: UObjectPropertyHeader {
                name: "TestInt".to_string(),
                arr_index: 0,
                r#type: data.get_string_type().to_owned(),
            },
            metadata: UObjectPropertyMetadata::None,
            data
        }
    }

    fn mkfloat(value: f32) -> UObjectProperty {
        let data = UObjectPropertyData::Float(value);
        UObjectProperty {
            header: UObjectPropertyHeader {
                name: "TestFloat".to_string(),
                arr_index: 0,
                r#type: data.get_string_type().to_owned(),
            },
            metadata: UObjectPropertyMetadata::None,
            data
        }
    }

    fn mkstr(value: &str) -> UObjectProperty {
        let data = UObjectPropertyData::String(value.to_string());
        UObjectProperty {
            header: UObjectPropertyHeader {
                name: "TestString".to_string(),
                arr_index: 0,
                r#type: data.get_string_type().to_owned(),
            },
            metadata: UObjectPropertyMetadata::None,
            data
        }
    }

    fn mkstr16(value: &str) -> UObjectProperty {
        let data = UObjectPropertyData::StringUtf16(value.to_string());
        UObjectProperty {
            header: UObjectPropertyHeader {
                name: "TestString".to_string(),
                arr_index: 0,
                r#type: data.get_string_type().to_owned(),
            },
            metadata: UObjectPropertyMetadata::None,
            data
        }
    }

    fn get_test_object() -> IoUObject {        
        IoUObject {
            summary: get_test_object_summary(),
            properties: vec![
                mkbool(true),
                mkbyte(25,0),
                mkint(77),
                mkfloat(192f32),
                mkstr("TEEESTString"),
                UObjectProperty {
                    header: UObjectPropertyHeader {
                        name: "TestMap".to_string(),
                        arr_index: 0,
                        r#type: "MapProperty".to_string(),
                    },
                    metadata: UObjectPropertyMetadata::Map("IntProperty".to_string(), "StructProperty".to_string()),
                    data: UObjectPropertyData::Map(vec![
                        (
                            UObjectPropertyData::Int32(0),
                            UObjectPropertyData::Struct(vec![
                                mkint(0),
                                mkint(1),
                                mkint(2),
                                mkfloat(3f32),
                            ], vec![])
                        ),
                        (
                            UObjectPropertyData::Int32(1),
                            UObjectPropertyData::Struct(vec![
                                mkbool(true),
                                mkbool(false),
                                mkbyte(7,7),
                                mkstr("MoreTesting"),
                            ], vec![])
                        ),
                        (
                            UObjectPropertyData::Int32(2),
                            UObjectPropertyData::Struct(vec![
                                UObjectProperty {
                                    header: UObjectPropertyHeader {
                                        name: "TestMap".to_string(), 
                                        arr_index: 0,
                                        r#type: "MapProperty".to_string()
                                    },
                                    metadata: UObjectPropertyMetadata::Map("StrProperty".to_string(), "IntProperty".to_string()),
                                    data: UObjectPropertyData::Map(vec![
                                        (UObjectPropertyData::String("Prop1".to_string()), UObjectPropertyData::Int32(5)),
                                        (UObjectPropertyData::String("TestProp2".to_string()), UObjectPropertyData::Int32(7)),
                                    ])
                                }
                            ], vec![])
                        ),
                        (
                            UObjectPropertyData::Int32(30),
                            UObjectPropertyData::Struct(vec![
                                mkstr("SkipMapKeys")
                            ], vec![])
                        ),
                        (
                            UObjectPropertyData::Int32(2),
                            UObjectPropertyData::Struct(vec![
                                UObjectProperty { 
                                    header: UObjectPropertyHeader {
                                        name: "TestMap".to_string(), 
                                        arr_index: 0,
                                        r#type: "MapProperty".to_string()
                                    },
                                    metadata: UObjectPropertyMetadata::Map("StrProperty".to_string(), "StructProperty".to_string()),
                                    data: UObjectPropertyData::Map(vec![
                                        (UObjectPropertyData::String("Prop1".to_string()), UObjectPropertyData::Struct(vec![
                                            mkstr("NestedStruct"),
                                            mkfloat(77f32),
                                        ], vec![])),
                                        (UObjectPropertyData::String("TestProp2".to_string()), UObjectPropertyData::Struct(vec![
                                            mkbyte(25,6),
                                            mkstr("TestEndMapOnNestedStruct"),
                                        ], vec![])),
                                    ])
                                }
                            ], vec![])
                        ),
                    ])
                },
                mkfloat(999f32),
                mkstr("End of the object"),
            ]
        }
    }

    fn assert_equality(a: &IoUObject, b: &IoUObject) {

        // Summary Header
        assert_eq!(a.summary.header.cooked_header_size, b.summary.header.cooked_header_size);
        assert_eq!(a.summary.header.export_bundles_offset, b.summary.header.export_bundles_offset);
        assert_eq!(a.summary.header.export_map_offset, b.summary.header.export_map_offset);
        assert_eq!(a.summary.header.graph_data_offset, b.summary.header.graph_data_offset);
        assert_eq!(a.summary.header.graph_data_size, b.summary.header.graph_data_size);
        assert_eq!(a.summary.header.import_map_offset, b.summary.header.import_map_offset);
        assert_eq!(a.summary.header.name, b.summary.header.name);
        assert_eq!(a.summary.header.name_map_hashes_offset, b.summary.header.name_map_hashes_offset);
        assert_eq!(a.summary.header.name_map_hashes_size, b.summary.header.name_map_hashes_size);
        assert_eq!(a.summary.header.name_map_names_offset, b.summary.header.name_map_names_offset);
        assert_eq!(a.summary.header.name_map_names_size, b.summary.header.name_map_names_size);
        assert_eq!(a.summary.header.package_flags, b.summary.header.package_flags);
        assert_eq!(a.summary.header.pad, b.summary.header.pad);
        assert_eq!(a.summary.header.source_name, b.summary.header.source_name);

        // Summary other properties
        assert_eq!(a.summary.name_map, b.summary.name_map);
        assert_eq!(a.summary.remaining_bytes, b.summary.remaining_bytes);

        // Properties
        assert_eq!(a.properties.len(), b.properties.len());
        for i in 0..a.properties.len() {
            assert_eq!(a.properties[i].header.name, b.properties[i].header.name);
            assert_eq!(a.properties[i].header.arr_index, b.properties[i].header.arr_index);
            assert_eq!(a.properties[i].data, b.properties[i].data);
        }
    }

    #[test]
    pub fn byte_serialization_is_consistent() {
        let test = get_test_object();

        let mut serialized_bytes = Cursor::new(vec![]);
        test.to_bytes::<_,LE>(&mut serialized_bytes);
        serialized_bytes.set_position(0);
        match IoUObject::from_buffer::<_,LE>(&mut serialized_bytes) {
            Ok(deserialized) => assert_equality(&deserialized, &test),
            Err(err) => panic!("{:?}",err.source()),
        }
    }

    #[test]
    pub fn string_serialization_is_consistent() {
        let test = get_test_object();

        let mut serialized_string = Cursor::new(vec![]);
        test.to_string(&mut serialized_string);
        serialized_string.set_position(0);

        // Print string to help with debugging purposes
        let string_content = String::from_utf8(serialized_string.clone().into_inner()).unwrap();
        println!("{string_content}");

        match IoUObject::from_string(&mut serialized_string) {
            Ok(deserialized) => assert_equality(&deserialized, &test),
            Err(err) => panic!("{:?}",err),
        }
    }

    fn verify_serialize_and_deserialize(test: IoUObject) {
        let mut serialized_string = Cursor::new(vec![]);
        test.to_string(&mut serialized_string);
        serialized_string.set_position(0);

        // Print string to help with debugging purposes
        let string_content = String::from_utf8(serialized_string.clone().into_inner()).unwrap();
        println!("{string_content}");

        match IoUObject::from_string(&mut serialized_string) {
            Ok(deserialized) => assert_equality(&deserialized, &test),
            Err(err) => panic!("{:?}",err),
        }

        let mut serialized_bytes = Cursor::new(vec![]);
        test.to_bytes::<_,LE>(&mut serialized_bytes);
        serialized_bytes.set_position(0);
        match IoUObject::from_buffer::<_,LE>(&mut serialized_bytes) {
            Ok(deserialized) => assert_equality(&deserialized, &test),
            Err(err) => panic!("{:?}",err),
        }
    }

    #[test]
    pub fn utf16_str_property() {
        let test = IoUObject {
            summary: get_test_object_summary(),
            properties: vec![
                mkstr16("Zażółć gęślą jaźń")
            ]
        };

        verify_serialize_and_deserialize(test);
    }

    #[test]
    pub fn array_property() {
        let test = IoUObject {
            summary: get_test_object_summary(),
            properties: vec![
                UObjectProperty {
                    header: UObjectPropertyHeader {
                        name: "TestArray".to_string(),
                        arr_index: 0,
                        r#type: "ArrayProperty".to_string(),
                    },
                    metadata: UObjectPropertyMetadata::Array("IntProperty".to_string()),
                    data: UObjectPropertyData::Array(vec![
                        UObjectPropertyData::Int32(7),
                        UObjectPropertyData::Int32(293),
                        UObjectPropertyData::Int32(353),
                        UObjectPropertyData::Int32(80),
                    ], None)
                },
                UObjectProperty {
                    header: UObjectPropertyHeader {
                        name: "TestArray".to_string(),
                        arr_index: 0,
                        r#type: "ArrayProperty".to_string()
                    },
                    metadata: UObjectPropertyMetadata::Array("StructProperty".to_string()),
                    data: UObjectPropertyData::Array(vec![
                        UObjectPropertyData::Struct(vec![mkstr("Test struct 1"), mkint(7), mkbool(true)], vec![]),
                        UObjectPropertyData::Struct(vec![mkstr("Test struct 2"), mkint(9), mkbool(false), mkint(10), mkstr("Yes")], vec![]),
                        UObjectPropertyData::Struct(vec![mkstr("Test struct 3"), mkbool(true), mkstr("No"), mkint(11)], vec![]),
                    ], Some((UObjectPropertyHeader { name: "TestStruct".to_string(), r#type: "StructProperty".to_string(), arr_index: 0}, "TestArray".to_string())))
                },
            ]
        };

        verify_serialize_and_deserialize(test);
    }

    #[test]
    fn empty_string() {
        let test = IoUObject {
            summary: get_test_object_summary(),
            properties: vec![mkstr("")]
        };

        verify_serialize_and_deserialize(test);
    }
}
