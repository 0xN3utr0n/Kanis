rule test_rule { 
	meta:
		description = "Generic test signature" 
		author = "0xN3utr0n" 	
	strings: 
		$a = "test-sample" 
		fullword condition: $a 
}

