import "pe"
import "console"
import "math"

private rule section_entropy_checker{
	condition:
		for all section in pe.sections:
		(
			
			(console.log("Entropy : ", math.entropy(section.raw_data_offset,section.raw_data_size))
			and console.log("Section Name : ", section.name)) 
			and
			console.hex("Magic Header Of Section : ", uint16be(section.raw_data_offset))
		)

}

rule resource_section_entropy{
	condition:
		for all resource in pe.resources:
		(
			console.log("Resource Entropy : ", math.entropy(resource.offset, resource.length)) and
			console.hex("Resource Magic Header : ", uint16be(resource.offset)) 
		)
}