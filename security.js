#!/usr/bin/env node
var argv=require('optimist')
	.usage('Usage: $0 -a [des|3des|aes]  -b [ecb|cbc] -k [hex string] -f [filepath]')
	.alias('a', 'alg')
	.alias('b', 'block')
	.alias('k', 'key')
	.alias('s', 'secondkey')
	.alias('d', 'decrypt')
	.alias('f', 'file')
	.alias('o', 'output')
	.alias('i', 'initvector')
	.demand(['a', 'b', 'k', 'f'])
	.default('d', false)
	.default('o', false)
	.string('k')
	.string('s')
	.string('i')
	.argv;
var fs=require('fs');

if(argv.b==='cbc'){
	if((argv.a==='aes'&&argv.i.match(/^[a-fA-F0-9]{16}$/)===null)||(((argv.a==='des')||(argv.a==='3des'))&&(argv.i.match(/^[a-fA-F0-9]{16}$/)===null))){
		console.log("Invalid initial vector");
		return;
	}
}

if(argv.a!=='des'&&argv.a!=='3des'&&argv.a!=='aes'){
	console.log("Invalid algorithm specified");
	return;
}

if(argv.b!=='ecb'&&argv.b!=='cbc'){
	console.log("Invalid block mode specified");
	return;
}

if(!fs.existsSync(argv.f)){
	console.log("Invalid source file");
	return;
}

if((argv.a==='des'||argv.a==='3des')&&argv.k.match(/^[a-fA-F0-9]{16}$/)===null){
	console.log("Invalid key");
	return;
}

if(argv.a==='aes'&&argv.k.match(/^[a-fA-F0-9]{32}$/)===null){
	console.log("Invalid key");
	return;
}

if((argv.a==='3des')&&(argv.s.match(/^[a-fA-F0-9]{16}$/)===null)){
	console.log("Invalid second key");
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

var boxes=[[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
						[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
						[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
						[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

						[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
						[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
						[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
						[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

						[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
						[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
						[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
						[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

						[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
						[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
						[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
						[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

						[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
						[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
						[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
						[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

						[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
						[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
						[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
						[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

						[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
						[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
						[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
						[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

						[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
						[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
						[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
						[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]];

var ptable=[[16, 7, 20, 21],
						[29, 12, 28, 17],
						[1, 15, 23, 26],
						[5, 18, 31, 10],
						[2, 8, 24, 14],
						[32, 27, 3, 9],
						[19, 13, 30, 6],
						[22, 11, 4, 25]];

var finalTable=[[40, 8, 48, 16, 56, 24, 64, 32],
								[39, 7, 47, 15, 55, 23, 63, 31],
								[38, 6, 46, 14, 54, 22, 62, 30],
								[37, 5, 45, 13, 53, 21, 61, 29],
								[36, 4, 44, 12, 52, 20, 60, 28],
								[35, 3, 43, 11, 51, 19, 59, 27],
								[34, 2, 42, 10, 50, 18, 58, 26],
								[33, 1, 41, 9, 49, 17, 57, 25]];

function xor(left, right){
	var temp="";
	for(var xorIter=0;xorIter<left.length;++xorIter){
		temp+=(left[xorIter]!==right[xorIter])?'1':'0';
	}
	return temp;
}

function hexToBin(str){
	var temp="";
	for(htbIter in str){
		temp+=("000"+parseInt(str[htbIter], 16).toString(2)).slice(-4);
	}
	return temp;
}

function hexToAscii(str){
	str=str.match(/.{2}/g);
	for(var htaIter=0;htaIter<str.length;++htaIter){
		str[htaIter]=String.fromCharCode(parseInt(str[htaIter], 16));
	}
	return str.join('');
}

function binToHex(str){
	str=str.match(/.{8}/g);
	for(var bthIter=0;bthIter<str.length;++bthIter){
		str[bthIter]=("0"+parseInt(str[bthIter], 2).toString(16)).slice(-2);
	}
	return str.join('').toUpperCase();
}

function binToAscii(str){
	str=str.match(/.{8}/g);
	for(var btaIter=0;btaIter<str.length;++btaIter){
		str[btaIter]=String.fromCharCode(("0000000"+parseInt(str[btaIter], 2)).slice(-8));
	}
	return str.join('');
}

function asciiToHex(str){
	var temp='';
	for(var athIter=0;athIter<str.length;++athIter){
		temp+=("0"+parseInt(str.charCodeAt(athIter)).toString(16)).slice(-2);
	}
	return temp;
}

function hexXor(left, right){
	return xor(hexToBin(left), hexToBin(right));
}

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

function sbox(block, box){
	var i=parseInt(block[0].concat(block[5]), 2);
	var j=parseInt(block.slice(1, 5), 2);
	return ("000"+box[i][j].toString(2)).slice(-4);
}

function ecbMangle(block, key){
	var temp=xor(key, getPermutation(block, eSelectionTable));
	temp=temp.match(/.{6}/g);
	for(var i=0;i<temp.length;++i){
		temp[i]=sbox(temp[i], boxes[i]);
	}
	return getPermutation(temp.join(''), ptable);
}

function desEncode(block, subkeys, hex){
	var ip=getPermutation(block, initialPermute);
	var halves=[[ip.slice(0, 32), ip.slice(-32)]];
	for(var i=1;i<=16;++i){
		halves.push([halves[i-1][1], xor(halves[i-1][0], ecbMangle(halves[i-1][1], subkeys[i-1]))]);
	}
	var temp=getPermutation(halves[16][1].concat(halves[16][0]), finalTable).match(/.{8}/g);
	for(chunk in temp){
		if(hex){
			temp[chunk]=("0"+parseInt(temp[chunk], 2).toString(16).toUpperCase()).slice(-2);
		}
		else{
			temp[chunk]=String.fromCharCode(parseInt(temp[chunk], 2));
		}
	}
	return temp.join('');
}

function desDecode(block, subkeys, hex){
	var ip=getPermutation(block, initialPermute);
	var halves=[[ip.slice(0, 32), ip.slice(-32)]];
	for(var i=1;i<=16;++i){
		halves.push([halves[i-1][1], xor(halves[i-1][0], ecbMangle(halves[i-1][1], subkeys[16-i]))]);
	}
	var temp=getPermutation(halves[16][1].concat(halves[16][0]), finalTable).match(/.{8}/g);
	for(chunk in temp){
		if(hex){
			temp[chunk]=("0"+parseInt(temp[chunk], 2).toString(16).toUpperCase()).slice(-2);
		}
		else{
			temp[chunk]=String.fromCharCode(parseInt(temp[chunk], 2));
		}
	}
	return temp.join('');
}

function getDesSubkeys(key){
	var keyhalves=[];
	var arr=[];
	key=key.split('');
	for(int in key){
		key[int]=(("000"+parseInt(key[int],16).toString(2)).slice(-4));
	}
	var permutedKey=getPermutation(key.join(''), permute1);
	keyhalves.push([permutedKey.slice(0, 28), permutedKey.slice(-28)]);
	for(var i=1;i<=16;++i){
		keyhalves.push(getNextHalf(keyhalves[i-1], (i===1||i===2||i===9||i===16)?1:2));
	}
	for(var i=1;i<=16;++i){
		arr.push(getPermutation(keyhalves[i].join(''), permute2));
	}
	return arr;
}

function desProcessMsg(msg, hex){
	var msgData="";
	if(hex){
		for(char in msg){
			msgData+=("000"+parseInt(msg[char], 16).toString(2)).slice(-4);
		}
	}
	else{
		for(char in msg){
			msgData+=("0000000"+msg.charCodeAt(char).toString(2)).slice(-8);
		}
	}
	while((msgData.length%64)!==0){
		msgData+='0';
	}
	return msgData.match(/.{64}/g);
}

function des(key, msg, decrypt, hexIn, hexOut){
	hexIn=(typeof(hexIn)==='undefined'||hexIn===null)?false:hexIn;
	hexOut=(typeof(hexOut)==='undefined'||hexOut===null)?true:hexOut;
	var subkeys=getDesSubkeys(key);
	var finalText=desProcessMsg(msg, hexIn);
	var ivDone=false;
	if(argv.b==='ecb'){
		for(block in finalText){
			finalText[block]=(decrypt)?desDecode(finalText[block], subkeys, hexOut):desEncode(finalText[block], subkeys, hexOut);
		}
	}
	else{
		for(block in finalText){
			if(!decrypt){
				if(!ivDone){
					finalText[block]=xor(finalText[block], hexToBin(argv.i));
					ivDone=true;
				}
				else{
					finalText[block]=xor(finalText[block], hexToBin(finalText[block-1]));
				}
				finalText[block]=desEncode(finalText[block], subkeys, hexOut);
			}
			else{
				if(block<finalText.length-1){
					finalText[finalText.length-block-1]=xor(hexToBin(desDecode(finalText[finalText.length-block-1], subkeys, true)), finalText[finalText.length-block-2]);
				}
				else{
					finalText[finalText.length-block-1]=hexXor(desDecode(finalText[finalText.length-block-1], subkeys, true), argv.i);
					ivDone=true;
				}
			}
		}
		if(decrypt){
			for(block in finalText){
				finalText[block]=(hexOut)?binToHex(finalText[block]):binToAscii(finalText[block]);
			}
		}
	}
	return finalText;
}

function tripleDes(keys, msg, decrypt){
	var finalText=(decrypt)?msg.match(/[\s\S.]{16}/g):msg.match(/[\s\S.]{8}/g);
	var ivDone=false;
	if(finalText===null){
		finalText=[msg];
	}
	if(finalText.join('')!==msg){
		finalText.push(msg.substr(finalText.length*8));
	}
	while(finalText[finalText.length-1].length<8){
		finalText[finalText.length-1]+=String.fromCharCode(0);
	}
	if(argv.b==="ecb"){
		for(var i=0;i<3;++i){
			for(triDesBlock in finalText){
				finalText[triDesBlock]=des((i===1)?keys[1]:keys[0], finalText[triDesBlock], (i%2===1)?(!decrypt):decrypt, (i!==0||decrypt), true).join('');
			}
		}
	}
	else{
		for(triDesBlock in finalText){
			if(!decrypt){
				if(!ivDone){
					finalText[triDesBlock]=binToHex(hexXor(asciiToHex(finalText[triDesBlock]), argv.i));
					ivDone=true;
				}
				else{
					finalText[triDesBlock]=binToHex(hexXor(asciiToHex(finalText[triDesBlock]), finalText[triDesBlock-1]));
				}
				for(var i=0;i<3;++i){
					finalText[triDesBlock]=des((i===1)?keys[1]:keys[0], finalText[triDesBlock], (i%2===1)?(!decrypt):decrypt, true, true).join('');
				}
			}
			else{
				if(triDesBlock<finalText.length-1){
					for(var i=0;i<3;++i){
						finalText[finalText.length-triDesBlock-1]=des((i===1)?keys[1]:keys[0], finalText[finalText.length-triDesBlock-1], (i%2===1)?(!decrypt):decrypt, true, true).join('');
					}
					finalText[finalText.length-triDesBlock-1]=binToHex(hexXor(finalText[finalText.length-triDesBlock-1], finalText[finalText.length-triDesBlock-2]));
				}
				else{
					for(var i=0;i<3;++i){
						finalText[finalText.length-triDesBlock-1]=des((i===1)?keys[1]:keys[0], finalText[finalText.length-triDesBlock-1], (i%2===1)?(!decrypt):decrypt, true, true).join('');
					}
					finalText[finalText.length-triDesBlock-1]=binToHex(hexXor(finalText[finalText.length-triDesBlock-1], argv.i));
					ivDone=true;
				}
			}
		}
	}
	if(decrypt){
		for(triDesBlock in finalText){
			finalText[triDesBlock]=hexToAscii(finalText[triDesBlock]);
		}
	}
	return finalText;
}

function aes(key, msg, decrypt){

}

var enc=(argv.a==='des')?des:(argv.a==='3des')?tripleDes:aes;
var finalText=enc((argv.a==='3des')?[argv.k, argv.s]:argv.k, fileData, argv.d, argv.d, !argv.d).join('');

if(argv.o){
	finalText+='\n';
	fs.writeFile(argv.o, finalText);
}
else{
	console.log(finalText);
}
