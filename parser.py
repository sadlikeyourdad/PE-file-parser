import pefile

def parse_pe_file(file_path):
    # Load the PE file
    pe = pefile.PE(file_path)

    # Basic information
    print("PE File Information")
    print("===================")
    print(f"File Path: {file_path}")
    print(f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
    print(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
    print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
    print(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
    print()

    # Sections
    print("Sections")
    print("========")
    for section in pe.sections:
        print(f"Name: {section.Name.decode().rstrip('\x00')}")
        print(f"Virtual Address: 0x{section.VirtualAddress:08X}")
        print(f"Size of Raw Data: {section.SizeOfRawData}")
        print(f"Characteristics: 0x{section.Characteristics:08X}")
        print()

    # Imports
    print("Imports")
    print("=======")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"Library: {entry.dll.decode()}")
            for imp in entry.imports:
                if imp.import_by_ordinal:
                    print(f"Ordinal: {str(imp.ordinal)}")
                else:
                    print(f"Function: {imp.name.decode()}")
            print()

    # Exports
    print("Exports")
    print("=======")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"Ordinal: {exp.ordinal}")
            print(f"Function: {exp.name.decode()}")
            print()

    # Resources
    print("Resources")
    print("=========")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                print(f"Resource Type: {resource_type.name.decode()}")
            else:
                print("Resource Type: None")
            for resource_id in resource_type.directory.entries:
                if resource_id.name is not None:
                    print(f"Resource ID: {resource_id.name.decode()}")
                else:
                    print("Resource ID: None")
                for resource_lang in resource_id.directory.entries:
                    print(f"Language: {hex(resource_lang.data.lang)}")
                    print(f"Sublanguage: {hex(resource_lang.data.sublang)}")
                    print(f"Offset: {resource_lang.data.struct.OffsetToData}")
                    print(f"Size: {resource_lang.data.struct.Size}")
                    print()

    # Close the PE file
    pe.close()

# Usage example
parse_pe_file("path/to/your/file.exe")
