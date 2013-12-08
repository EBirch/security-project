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
if(fileData===''){
	console.log("Invalid file");
	return;
}

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
	return temp.toUpperCase();
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

function getState(msg){
	var matrix=[[],[],[],[]];
	var cols=msg.match(/.{8}/g);
	for(group in cols){
		var temp=cols[group].match(/.{2}/g);
		for(row in matrix){
			matrix[row][group]=temp[row];
		}
	}
	return matrix;
}

function subBytes(word, sbox){
	var temp="";
	var pairs=word.match(/.{2}/g);
	for(pair in pairs){
		temp+=sbox[parseInt(pairs[pair][0], 16)][parseInt(pairs[pair][1], 16)];
	}
	return temp.toUpperCase();
}

function rotate(word){
	return word.slice(-6).concat(word.slice(0, 2));
}

function getAesWords(key){
	var words=key.match(/.{8}/g);
	for(var i=1;i<11;++i){
		var roundConst=1;
		var newWord=binToHex(hexXor(subBytes(rotate(words[(i*4)-1]), aesSbox), aesRoundConsts[i]));
		words.push(binToHex(hexXor(newWord, words[(i-1)*4])));
		for(var j=1;j<4;++j){
			words.push(binToHex(hexXor(words[((i-1)*4)+j], words[((i-1)*4)+j+3])));
		}
	}
	return words;
}

function xorAesState(state, words){
	for(row in state){
		for(col in state[row]){
			state[row][col]=binToHex(hexXor(state[row][col], words[col].slice(row*2, (row*2)+2)));
		}
	}
	return state;
}

function getMultVal(pair, val){
	if(val===1){
		return pair;
	}
	return mixColsMultTables[val][parseInt(pair[0], 16)][parseInt(pair[1], 16)];
}

function mixCols(state, matrix){
	var newState=[[],[],[],[]];
	for(row in state){
		for(col in state[row]){
			newState[row][col]=binToHex(xor(hexXor(getMultVal(state[0][col], matrix[0][row]), 
																					getMultVal(state[1][col], matrix[1][row])), 
																	hexXor(getMultVal(state[2][col], matrix[2][row]), 
																				getMultVal(state[3][col], matrix[3][row]))));
		}
	}
	return newState;
}

function doAesRound(state, key, last){
	for(row in state){
		for(col in state[row]){
			state[row][col]=subBytes(state[row][col], aesSbox);
		}
	}
	for(row in state){
		if(row==0){
			continue;
		}
		state[row]=state[row].slice(-(4-row)).concat(state[row].slice(0, row));
	}
	if(!last){
		state=mixCols(state, mixColsMatrix);
	}
	state=xorAesState(state, key);
	return state;
}

function doAesDecryptRound(state, key, last){
	for(row in state){
		if(row==0){
			continue;
		}
		state[row]=state[row].slice(-row).concat(state[row].slice(0, 4-row));
	}
	for(row in state){
		for(col in state[row]){
			state[row][col]=subBytes(state[row][col], invAesSbox);
		}
	}
	state=xorAesState(state, key);
	if(!last){
		state=mixCols(state, mixColsInvMatrix);
	}
	return state;
}

function aesEncode(words, msg){
	var state=getState(msg);
	state=xorAesState(state, words.slice(0, 4));
	for(var roundNum=1;roundNum<11;++roundNum){
		state=doAesRound(state, words.slice(roundNum*4, (roundNum+1)*4), (roundNum===10));
	}
	var temp=[[],[],[],[]];
	for(row in state){
		for(col in state[row]){
			temp[row][col]=state[col][row];
		}
		temp[row]=temp[row].join('');
	}
	return temp.join('');
}

function aesDecode(words, msg){
	var state=getState(msg);
	state=xorAesState(state, words.slice(-4));
	for(var roundNum=1;roundNum<11;++roundNum){
		state=doAesDecryptRound(state, words.slice(-((roundNum+1)*4), -(roundNum*4)), (roundNum===10));
	}
	var temp=[[],[],[],[]];
	for(row in state){
		for(col in state[row]){
			temp[row][col]=state[col][row];
		}
		temp[row]=temp[row].join('');
	}
	return temp.join('');
}

function aes(key, msg, decrypt){
	var finalText=(decrypt)?msg:asciiToHex(msg);
	while(finalText.length%32!==0){
		finalText+='00';
	}
	finalText=finalText.match(/.{32}/g);
	var words=getAesWords(key);
	if(argv.b==='ecb'){
		for(block in finalText){
			finalText[block]=(!decrypt)?aesEncode(words, finalText[block]):aesDecode(words, finalText[block]);
		}
	}
	if(decrypt){
		for(block in finalText){
			finalText[block]=hexToAscii(finalText[block]);
		}
	}
	return finalText;
}

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

var aesSbox=[["63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"],
						["ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"],
						["b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"],
						["04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"],
						["09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"],
						["53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"],
						["d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"],
						["51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"],
						["cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"],
						["60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"],
						["e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"],
						["e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"],
						["ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"],
						["70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"],
						["e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"],
						["8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"]]

var invAesSbox=[["52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"],
								["7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"],
								["54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"],
								["08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"],
								["72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"],
								["6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"],
								["90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"],
								["d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"],
								["3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"],
								["96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"],
								["47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"],
								["fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"],
								["1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"],
								["60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"],
								["a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"],
								["17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"]];

var aesRoundConsts=["0", "01000000", "02000000", "04000000", "08000000", "10000000", "20000000", "40000000", "80000000", "1b000000", "36000000"];

var mixColsMatrix=[[2, 1, 1, 3],
									[3, 2, 1, 1],
									[1, 3, 2, 1],
									[1, 1, 3, 2]];

var mixColsInvMatrix=[[14, 9, 13, 11],
											[11, 14, 9, 13],
											[13, 11, 14, 9],
											[9, 13, 11, 14]];

var mixColsMultTables={2:[["00", "02", "04", "06", "08", "0a", "0c", "0e", "10", "12", "14", "16", "18", "1a", "1c", "1e"],
												["20", "22", "24", "26", "28", "2a", "2c", "2e", "30", "32", "34", "36", "38", "3a", "3c", "3e"],
												["40", "42", "44", "46", "48", "4a", "4c", "4e", "50", "52", "54", "56", "58", "5a", "5c", "5e"],
												["60", "62", "64", "66", "68", "6a", "6c", "6e", "70", "72", "74", "76", "78", "7a", "7c", "7e"],
												["80", "82", "84", "86", "88", "8a", "8c", "8e", "90", "92", "94", "96", "98", "9a", "9c", "9e"],
												["a0", "a2", "a4", "a6", "a8", "aa", "ac", "ae", "b0", "b2", "b4", "b6", "b8", "ba", "bc", "be"],
												["c0", "c2", "c4", "c6", "c8", "ca", "cc", "ce", "d0", "d2", "d4", "d6", "d8", "da", "dc", "de"],
												["e0", "e2", "e4", "e6", "e8", "ea", "ec", "ee", "f0", "f2", "f4", "f6", "f8", "fa", "fc", "fe"],
												["1b", "19", "1f", "1d", "13", "11", "17", "15", "0b", "09", "0f", "0d", "03", "01", "07", "05"],
												["3b", "39", "3f", "3d", "33", "31", "37", "35", "2b", "29", "2f", "2d", "23", "21", "27", "25"],
												["5b", "59", "5f", "5d", "53", "51", "57", "55", "4b", "49", "4f", "4d", "43", "41", "47", "45"],
												["7b", "79", "7f", "7d", "73", "71", "77", "75", "6b", "69", "6f", "6d", "63", "61", "67", "65"],
												["9b", "99", "9f", "9d", "93", "91", "97", "95", "8b", "89", "8f", "8d", "83", "81", "87", "85"],
												["bb", "b9", "bf", "bd", "b3", "b1", "b7", "b5", "ab", "a9", "af", "ad", "a3", "a1", "a7", "a5"],
												["db", "d9", "df", "dd", "d3", "d1", "d7", "d5", "cb", "c9", "cf", "cd", "c3", "c1", "c7", "c5"],
												["fb", "f9", "ff", "fd", "f3", "f1", "f7", "f5", "eb", "e9", "ef", "ed", "e3", "e1", "e7", "e5"]]
											,3:[["00", "03", "06", "05", "0c", "0f", "0a", "09", "18", "1b", "1e", "1d", "14", "17", "12", "11"],
												["30", "33", "36", "35", "3c", "3f", "3a", "39", "28", "2b", "2e", "2d", "24", "27", "22", "21"],
												["60", "63", "66", "65", "6c", "6f", "6a", "69", "78", "7b", "7e", "7d", "74", "77", "72", "71"],
												["50", "53", "56", "55", "5c", "5f", "5a", "59", "48", "4b", "4e", "4d", "44", "47", "42", "41"],
												["c0", "c3", "c6", "c5", "cc", "cf", "ca", "c9", "d8", "db", "de", "dd", "d4", "d7", "d2", "d1"],
												["f0", "f3", "f6", "f5", "fc", "ff", "fa", "f9", "e8", "eb", "ee", "ed", "e4", "e7", "e2", "e1"],
												["a0", "a3", "a6", "a5", "ac", "af", "aa", "a9", "b8", "bb", "be", "bd", "b4", "b7", "b2", "b1"],
												["90", "93", "96", "95", "9c", "9f", "9a", "99", "88", "8b", "8e", "8d", "84", "87", "82", "81"],
												["9b", "98", "9d", "9e", "97", "94", "91", "92", "83", "80", "85", "86", "8f", "8c", "89", "8a"],
												["ab", "a8", "ad", "ae", "a7", "a4", "a1", "a2", "b3", "b0", "b5", "b6", "bf", "bc", "b9", "ba"],
												["fb", "f8", "fd", "fe", "f7", "f4", "f1", "f2", "e3", "e0", "e5", "e6", "ef", "ec", "e9", "ea"],
												["cb", "c8", "cd", "ce", "c7", "c4", "c1", "c2", "d3", "d0", "d5", "d6", "df", "dc", "d9", "da"],
												["5b", "58", "5d", "5e", "57", "54", "51", "52", "43", "40", "45", "46", "4f", "4c", "49", "4a"],
												["6b", "68", "6d", "6e", "67", "64", "61", "62", "73", "70", "75", "76", "7f", "7c", "79", "7a"],
												["3b", "38", "3d", "3e", "37", "34", "31", "32", "23", "20", "25", "26", "2f", "2c", "29", "2a"],
												["0b", "08", "0d", "0e", "07", "04", "01", "02", "13", "10", "15", "16", "1f", "1c", "19", "1a"]]
											,9:[["00" ,"09" ,"12" ,"1b" ,"24" ,"2d" ,"36" ,"3f" ,"48" ,"41" ,"5a" ,"53" ,"6c" ,"65" ,"7e" ,"77"],
												["90" ,"99" ,"82" ,"8b" ,"b4" ,"bd" ,"a6" ,"af" ,"d8" ,"d1" ,"ca" ,"c3" ,"fc" ,"f5" ,"ee" ,"e7"],
												["3b" ,"32" ,"29" ,"20" ,"1f" ,"16" ,"0d" ,"04" ,"73" ,"7a" ,"61" ,"68" ,"57" ,"5e" ,"45" ,"4c"],
												["ab" ,"a2" ,"b9" ,"b0" ,"8f" ,"86" ,"9d" ,"94" ,"e3" ,"ea" ,"f1" ,"f8" ,"c7" ,"ce" ,"d5" ,"dc"],
												["76" ,"7f" ,"64" ,"6d" ,"52" ,"5b" ,"40" ,"49" ,"3e" ,"37" ,"2c" ,"25" ,"1a" ,"13" ,"08" ,"01"],
												["e6" ,"ef" ,"f4" ,"fd" ,"c2" ,"cb" ,"d0" ,"d9" ,"ae" ,"a7" ,"bc" ,"b5" ,"8a" ,"83" ,"98" ,"91"],
												["4d" ,"44" ,"5f" ,"56" ,"69" ,"60" ,"7b" ,"72" ,"05" ,"0c" ,"17" ,"1e" ,"21" ,"28" ,"33" ,"3a"],
												["dd" ,"d4" ,"cf" ,"c6" ,"f9" ,"f0" ,"eb" ,"e2" ,"95" ,"9c" ,"87" ,"8e" ,"b1" ,"b8" ,"a3" ,"aa"],
												["ec" ,"e5" ,"fe" ,"f7" ,"c8" ,"c1" ,"da" ,"d3" ,"a4" ,"ad" ,"b6" ,"bf" ,"80" ,"89" ,"92" ,"9b"],
												["7c" ,"75" ,"6e" ,"67" ,"58" ,"51" ,"4a" ,"43" ,"34" ,"3d" ,"26" ,"2f" ,"10" ,"19" ,"02" ,"0b"],
												["d7" ,"de" ,"c5" ,"cc" ,"f3" ,"fa" ,"e1" ,"e8" ,"9f" ,"96" ,"8d" ,"84" ,"bb" ,"b2" ,"a9" ,"a0"],
												["47" ,"4e" ,"55" ,"5c" ,"63" ,"6a" ,"71" ,"78" ,"0f" ,"06" ,"1d" ,"14" ,"2b" ,"22" ,"39" ,"30"],
												["9a" ,"93" ,"88" ,"81" ,"be" ,"b7" ,"ac" ,"a5" ,"d2" ,"db" ,"c0" ,"c9" ,"f6" ,"ff" ,"e4" ,"ed"],
												["0a" ,"03" ,"18" ,"11" ,"2e" ,"27" ,"3c" ,"35" ,"42" ,"4b" ,"50" ,"59" ,"66" ,"6f" ,"74" ,"7d"],
												["a1" ,"a8" ,"b3" ,"ba" ,"85" ,"8c" ,"97" ,"9e" ,"e9" ,"e0" ,"fb" ,"f2" ,"cd" ,"c4" ,"df" ,"d6"],
												["31" ,"38" ,"23" ,"2a" ,"15" ,"1c" ,"07" ,"0e" ,"79" ,"70" ,"6b" ,"62" ,"5d" ,"54" ,"4f" ,"46"]]
											,11:[["00" ,"0b" ,"16" ,"1d" ,"2c" ,"27" ,"3a" ,"31" ,"58" ,"53" ,"4e" ,"45" ,"74" ,"7f" ,"62" ,"69"],
												["b0" ,"bb" ,"a6" ,"ad" ,"9c" ,"97" ,"8a" ,"81" ,"e8" ,"e3" ,"fe" ,"f5" ,"c4" ,"cf" ,"d2" ,"d9"],
												["7b" ,"70" ,"6d" ,"66" ,"57" ,"5c" ,"41" ,"4a" ,"23" ,"28" ,"35" ,"3e" ,"0f" ,"04" ,"19" ,"12"],
												["cb" ,"c0" ,"dd" ,"d6" ,"e7" ,"ec" ,"f1" ,"fa" ,"93" ,"98" ,"85" ,"8e" ,"bf" ,"b4" ,"a9" ,"a2"],
												["f6" ,"fd" ,"e0" ,"eb" ,"da" ,"d1" ,"cc" ,"c7" ,"ae" ,"a5" ,"b8" ,"b3" ,"82" ,"89" ,"94" ,"9f"],
												["46" ,"4d" ,"50" ,"5b" ,"6a" ,"61" ,"7c" ,"77" ,"1e" ,"15" ,"08" ,"03" ,"32" ,"39" ,"24" ,"2f"],
												["8d" ,"86" ,"9b" ,"90" ,"a1" ,"aa" ,"b7" ,"bc" ,"d5" ,"de" ,"c3" ,"c8" ,"f9" ,"f2" ,"ef" ,"e4"],
												["3d" ,"36" ,"2b" ,"20" ,"11" ,"1a" ,"07" ,"0c" ,"65" ,"6e" ,"73" ,"78" ,"49" ,"42" ,"5f" ,"54"],
												["f7" ,"fc" ,"e1" ,"ea" ,"db" ,"d0" ,"cd" ,"c6" ,"af" ,"a4" ,"b9" ,"b2" ,"83" ,"88" ,"95" ,"9e"],
												["47" ,"4c" ,"51" ,"5a" ,"6b" ,"60" ,"7d" ,"76" ,"1f" ,"14" ,"09" ,"02" ,"33" ,"38" ,"25" ,"2e"],
												["8c" ,"87" ,"9a" ,"91" ,"a0" ,"ab" ,"b6" ,"bd" ,"d4" ,"df" ,"c2" ,"c9" ,"f8" ,"f3" ,"ee" ,"e5"],
												["3c" ,"37" ,"2a" ,"21" ,"10" ,"1b" ,"06" ,"0d" ,"64" ,"6f" ,"72" ,"79" ,"48" ,"43" ,"5e" ,"55"],
												["01" ,"0a" ,"17" ,"1c" ,"2d" ,"26" ,"3b" ,"30" ,"59" ,"52" ,"4f" ,"44" ,"75" ,"7e" ,"63" ,"68"],
												["b1" ,"ba" ,"a7" ,"ac" ,"9d" ,"96" ,"8b" ,"80" ,"e9" ,"e2" ,"ff" ,"f4" ,"c5" ,"ce" ,"d3" ,"d8"],
												["7a" ,"71" ,"6c" ,"67" ,"56" ,"5d" ,"40" ,"4b" ,"22" ,"29" ,"34" ,"3f" ,"0e" ,"05" ,"18" ,"13"],
												["ca" ,"c1" ,"dc" ,"d7" ,"e6" ,"ed" ,"f0" ,"fb" ,"92" ,"99" ,"84" ,"8f" ,"be" ,"b5" ,"a8" ,"a3"]]
											,13:[["00" ,"0d" ,"1a" ,"17" ,"34" ,"39" ,"2e" ,"23" ,"68" ,"65" ,"72" ,"7f" ,"5c" ,"51" ,"46" ,"4b"],
												["d0" ,"dd" ,"ca" ,"c7" ,"e4" ,"e9" ,"fe" ,"f3" ,"b8" ,"b5" ,"a2" ,"af" ,"8c" ,"81" ,"96" ,"9b"],
												["bb" ,"b6" ,"a1" ,"ac" ,"8f" ,"82" ,"95" ,"98" ,"d3" ,"de" ,"c9" ,"c4" ,"e7" ,"ea" ,"fd" ,"f0"],
												["6b" ,"66" ,"71" ,"7c" ,"5f" ,"52" ,"45" ,"48" ,"03" ,"0e" ,"19" ,"14" ,"37" ,"3a" ,"2d" ,"20"],
												["6d" ,"60" ,"77" ,"7a" ,"59" ,"54" ,"43" ,"4e" ,"05" ,"08" ,"1f" ,"12" ,"31" ,"3c" ,"2b" ,"26"],
												["bd" ,"b0" ,"a7" ,"aa" ,"89" ,"84" ,"93" ,"9e" ,"d5" ,"d8" ,"cf" ,"c2" ,"e1" ,"ec" ,"fb" ,"f6"],
												["d6" ,"db" ,"cc" ,"c1" ,"e2" ,"ef" ,"f8" ,"f5" ,"be" ,"b3" ,"a4" ,"a9" ,"8a" ,"87" ,"90" ,"9d"],
												["06" ,"0b" ,"1c" ,"11" ,"32" ,"3f" ,"28" ,"25" ,"6e" ,"63" ,"74" ,"79" ,"5a" ,"57" ,"40" ,"4d"],
												["da" ,"d7" ,"c0" ,"cd" ,"ee" ,"e3" ,"f4" ,"f9" ,"b2" ,"bf" ,"a8" ,"a5" ,"86" ,"8b" ,"9c" ,"91"],
												["0a" ,"07" ,"10" ,"1d" ,"3e" ,"33" ,"24" ,"29" ,"62" ,"6f" ,"78" ,"75" ,"56" ,"5b" ,"4c" ,"41"],
												["61" ,"6c" ,"7b" ,"76" ,"55" ,"58" ,"4f" ,"42" ,"09" ,"04" ,"13" ,"1e" ,"3d" ,"30" ,"27" ,"2a"],
												["b1" ,"bc" ,"ab" ,"a6" ,"85" ,"88" ,"9f" ,"92" ,"d9" ,"d4" ,"c3" ,"ce" ,"ed" ,"e0" ,"f7" ,"fa"],
												["b7" ,"ba" ,"ad" ,"a0" ,"83" ,"8e" ,"99" ,"94" ,"df" ,"d2" ,"c5" ,"c8" ,"eb" ,"e6" ,"f1" ,"fc"],
												["67" ,"6a" ,"7d" ,"70" ,"53" ,"5e" ,"49" ,"44" ,"0f" ,"02" ,"15" ,"18" ,"3b" ,"36" ,"21" ,"2c"],
												["0c" ,"01" ,"16" ,"1b" ,"38" ,"35" ,"22" ,"2f" ,"64" ,"69" ,"7e" ,"73" ,"50" ,"5d" ,"4a" ,"47"],
												["dc" ,"d1" ,"c6" ,"cb" ,"e8" ,"e5" ,"f2" ,"ff" ,"b4" ,"b9" ,"ae" ,"a3" ,"80" ,"8d" ,"9a" ,"97"]]
											,14:[["00" ,"0e" ,"1c" ,"12" ,"38" ,"36" ,"24" ,"2a" ,"70" ,"7e" ,"6c" ,"62" ,"48" ,"46" ,"54" ,"5a"],
												["e0" ,"ee" ,"fc" ,"f2" ,"d8" ,"d6" ,"c4" ,"ca" ,"90" ,"9e" ,"8c" ,"82" ,"a8" ,"a6" ,"b4" ,"ba"],
												["db" ,"d5" ,"c7" ,"c9" ,"e3" ,"ed" ,"ff" ,"f1" ,"ab" ,"a5" ,"b7" ,"b9" ,"93" ,"9d" ,"8f" ,"81"],
												["3b" ,"35" ,"27" ,"29" ,"03" ,"0d" ,"1f" ,"11" ,"4b" ,"45" ,"57" ,"59" ,"73" ,"7d" ,"6f" ,"61"],
												["ad" ,"a3" ,"b1" ,"bf" ,"95" ,"9b" ,"89" ,"87" ,"dd" ,"d3" ,"c1" ,"cf" ,"e5" ,"eb" ,"f9" ,"f7"],
												["4d" ,"43" ,"51" ,"5f" ,"75" ,"7b" ,"69" ,"67" ,"3d" ,"33" ,"21" ,"2f" ,"05" ,"0b" ,"19" ,"17"],
												["76" ,"78" ,"6a" ,"64" ,"4e" ,"40" ,"52" ,"5c" ,"06" ,"08" ,"1a" ,"14" ,"3e" ,"30" ,"22" ,"2c"],
												["96" ,"98" ,"8a" ,"84" ,"ae" ,"a0" ,"b2" ,"bc" ,"e6" ,"e8" ,"fa" ,"f4" ,"de" ,"d0" ,"c2" ,"cc"],
												["41" ,"4f" ,"5d" ,"53" ,"79" ,"77" ,"65" ,"6b" ,"31" ,"3f" ,"2d" ,"23" ,"09" ,"07" ,"15" ,"1b"],
												["a1" ,"af" ,"bd" ,"b3" ,"99" ,"97" ,"85" ,"8b" ,"d1" ,"df" ,"cd" ,"c3" ,"e9" ,"e7" ,"f5" ,"fb"],
												["9a" ,"94" ,"86" ,"88" ,"a2" ,"ac" ,"be" ,"b0" ,"ea" ,"e4" ,"f6" ,"f8" ,"d2" ,"dc" ,"ce" ,"c0"],
												["7a" ,"74" ,"66" ,"68" ,"42" ,"4c" ,"5e" ,"50" ,"0a" ,"04" ,"16" ,"18" ,"32" ,"3c" ,"2e" ,"20"],
												["ec" ,"e2" ,"f0" ,"fe" ,"d4" ,"da" ,"c8" ,"c6" ,"9c" ,"92" ,"80" ,"8e" ,"a4" ,"aa" ,"b8" ,"b6"],
												["0c" ,"02" ,"10" ,"1e" ,"34" ,"3a" ,"28" ,"26" ,"7c" ,"72" ,"60" ,"6e" ,"44" ,"4a" ,"58" ,"56"],
												["37" ,"39" ,"2b" ,"25" ,"0f" ,"01" ,"13" ,"1d" ,"47" ,"49" ,"5b" ,"55" ,"7f" ,"71" ,"63" ,"6d"],
												["d7" ,"d9" ,"cb" ,"c5" ,"ef" ,"e1" ,"f3" ,"fd" ,"a7" ,"a9" ,"bb" ,"b5" ,"9f" ,"91" ,"83" ,"8d"]]};

var enc=(argv.a==='des')?des:(argv.a==='3des')?tripleDes:aes;
var finalText=enc((argv.a==='3des')?[argv.k, argv.s]:argv.k, fileData, argv.d, argv.d, !argv.d).join('');

if(argv.o){
	finalText+='\n';
	fs.writeFile(argv.o, finalText);
}
else{
	console.log(finalText);
}