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

var permute1=[[57, 49, 41, 33, 25, 17, 9],
							[1, 58, 50, 42, 34, 26, 18],
							[10, 2, 59, 51, 43, 35, 27],
							[19, 11, 3, 60, 52, 44, 36],
							[63, 55, 47, 39, 31, 23, 15],
							[7, 62, 54, 46, 38, 30, 22],
							[14, 6, 61, 53, 45, 37, 29],
							[21, 13, 5, 28, 20, 12, 4]];

var permute2=[[14, 17, 11, 24, 1, 5],
							[3, 28, 15, 6, 21, 10],
							[23, 19, 12, 4, 26, 8],
							[16, 7, 27, 20, 13, 2],
							[41, 52, 31, 37, 47, 55],
							[30, 40, 51, 45, 33, 48],
							[44, 49, 39, 56, 34, 53],
							[46, 42, 50, 36, 29, 32]];

var initialPermute=[[58, 50, 42, 34, 26, 18, 10, 2],
										[60, 52, 44, 36, 28, 20, 12, 4],
										[62, 54, 46, 38, 30, 22, 14, 6],
										[64, 56, 48, 40, 32, 24, 16, 8],
										[57, 49, 41, 33, 25, 17, 9, 1],
										[59, 51, 43, 35, 27, 19, 11, 3],
										[61, 53, 45, 37, 29, 21, 13, 5],
										[63, 55, 47, 39, 31, 23, 15, 7]];

var eSelectionTable=[[32, 1, 2, 3, 4, 5],
											[4, 5, 6, 7, 8, 9],
											[8, 9, 10, 11, 12, 13],
											[12, 13, 14, 15, 16, 17],
											[16, 17, 18, 19, 20, 21],
											[20, 21, 22, 23, 24, 25],
											[24, 25, 26, 27, 28, 29],
											[28, 29, 30, 31, 32, 1]];

function getPermutation(str, table){
	var temp="";
	for(row in table){
		for(col in table[row]){
			temp+=str[table[row][col]-1];
		}
	}
	return temp;
};

function getNextHalf(halves, shift){
	return [halves[0].slice(shift, halves[0].length).concat(halves[0].slice(0, shift)), halves[1].slice(shift, halves[1].length).concat(halves[1].slice(0, shift))];
}

function ecbMangle(block, key){

}

function ecbEncode(block){
	var ip=getPermutation(block, initialPermute);
	var halves=[[ip.slice(0, 32), ip.slice(-32)]];
	for(var i=1;i<=16;++i){
		halves.push([halves[i-1][1], parseInt(halves[i-1][0], 2)^parseInt(ecbMangle(halves[i-1][1], subkeys[i-1])]), 2);
	}
	return halves[16][0].concat(halves[16][1]);
}

var key=argv.k.split('');
var subkeys=[];
var keyhalves=[];
if(argv.k.match(/^[a-fA-F0-9]{16}$/)===null){
	console.log("Invalid key");
	return;
}
for(int in key){
	key[int]=(("000"+parseInt(key[int],16).toString(2)).slice(-4));
}
var permutedKey=getPermutation(key.join(''), permute1);
keyhalves.push([permutedKey.slice(0, 28), permutedKey.slice(-28)]);

for(var i=1;i<=16;++i){
	keyhalves.push(getNextHalf(keyhalves[i-1], (i===1||i===2||i===9||i===16)?1:2));
}

for(var i=1;i<=16;++i){
	subkeys.push(getPermutation(keyhalves[i].join(''), permute2));
}

var msgData="";
for(char in fileData){
	msgData+=("0000000"+fileData.charCodeAt(char).toString(2)).slice(-8);
	// msgData+=' ';
}

while((msgData.length%64)!==0){
	msgData+='0';
}

msgData=msgData.match(/.{64}/g);

if(!argv.d){
	var cleartext="";
	for(block in msgData){
		if(argv.b==="ecb"){
			cleartext+=ecbEncode(msgData[block]);
		}
	}
}

//console.log(msgData);
// console.log(fileData);
// console.log(key)
// console.log(key.length);return;
// console.log(getPermutation(key.join(''), pc1));
// console.log(hexdata)

// key=key.join('');
// console.log(key.split(/(.{4})/).filter(Boolean))
