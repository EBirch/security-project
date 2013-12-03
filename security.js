#!/usr/bin/env node
var argv=require('optimist')
	.usage('Usage: $0 -a [des|3des|aes]  -b [ecb|cbc] -k [string] -f [filepath]')
	.alias('a', 'alg')
	.alias('b', 'block')
	.alias('k', 'key')
	.alias('d', 'decrypt')
	.alias('f', 'file')
	.demand(['a', 'b', 'k', 'f'])
	.default('d', false)
	.argv;
var fs=require('fs');

if(!fs.existsSync(argv.f)){
	console.log("Invalid source file");
	return;
}
var fileData=fs.readFileSync(argv.f, 'utf8');
// fs.exists(argv.f, function(exists){
// 	if(!exists){
// 		console.log("Invalid source file");
// 		return;
// 	}
// 	fs.readFile(argv.f, {encoding:String}, function(err, data){
// 		if(err){
// 			console.log(err);
// 		}
// 		fileData=data;
// 		console.log(data);
// 	});
// });
var key=argv.k.split('');
if(argv.k.match(/^[a-fA-F0-9]{16}$/)===null){
	console.log("Invalid key");
	return;
}
for(int in key){
	key[int]=(("000"+parseInt(key[int],16).toString(2)).slice(-4));
}
console.log(fileData);

// key=key.join('');
// console.log(key.split(/(.{4})/).filter(Boolean))
