if(typeof Module==="undefined"){var Module={};}
var liboprf_module=
function(liboprf_module) {
  liboprf_module = liboprf_module || {};

var Module=liboprf_module;var readyPromiseResolve,readyPromiseReject;Module["ready"]=new Promise(function(resolve,reject){readyPromiseResolve=resolve;readyPromiseReject=reject});var ENVIRONMENT_IS_NODE=typeof process==="object";function ready(){readyPromiseResolve(Module)}function randomValueSetup(){if(Module.getRandomValue===undefined){try{var window_="object"===typeof window?window:self;var crypto_=typeof window_.crypto!=="undefined"?window_.crypto:window_.msCrypto;var randomValuesStandard=function(){var buf=new Uint32Array(1);crypto_.getRandomValues(buf);return buf[0]>>>0};randomValuesStandard();Module.getRandomValue=randomValuesStandard}catch(e){try{import("crypto").then(crypto=>{var randomValueNodeJS=function(){var buf=crypto["randomBytes"](4);return(buf[0]<<24|buf[1]<<16|buf[2]<<8|buf[3])>>>0};randomValueNodeJS();Module.getRandomValue=randomValueNodeJS})}catch(e){throw"No secure random number generator found"}}}}randomValueSetup();for(var base64ReverseLookup=new Uint8Array(123),i=25;i>=0;--i){base64ReverseLookup[48+i]=52+i;base64ReverseLookup[65+i]=i;base64ReverseLookup[97+i]=26+i}base64ReverseLookup[43]=62;base64ReverseLookup[47]=63;function base64Decode(b64){if(typeof ENVIRONMENT_IS_NODE!=="undefined"&&ENVIRONMENT_IS_NODE){try{var buf=Buffer.from(b64,"base64")}catch(_){var buf=new Buffer(b64,"base64")}return new Uint8Array(buf.buffer,buf.byteOffset,buf.byteLength)}var b1,b2,i=0,j=0,bLength=b64.length,output=new Uint8Array((bLength*3>>2)-(b64[bLength-2]=="=")-(b64[bLength-1]=="="));for(;i<bLength;i+=4,j+=3){b1=base64ReverseLookup[b64.charCodeAt(i+1)];b2=base64ReverseLookup[b64.charCodeAt(i+2)];output[j]=base64ReverseLookup[b64.charCodeAt(i)]<<2|b1>>4;output[j+1]=b1<<4|b2>>2;output[j+2]=b2<<6|base64ReverseLookup[b64.charCodeAt(i+3)]}return output}Module["wasm"]=base64Decode("AGFzbQEAAAABRgxgAn9/AGADf39/AGAEf39/fwBgA39/fwF/YAF/AGABfwF/YAJ+fwF+YAN/f34AYAF/AX5gAn9/AX9gAABgBn9/f39/fwACBwEBYQFhAAMDNTQGAQABBwgBAQEBBAABAAEACQADAAEAAAAFAAACBAAAAAUFAQMEAAAKAgABAAABAQILAgEABAUBcAEBAQUEAQECAgYIAX8BQfCXBAsHJQkBYgIAAWMAKAFkABIBZQA0AWYBAAFnADMBaAApAWkAMgFqADEKl5UBNAgAIAAgAa2KC50JAid+DH8gACACKAIEIiqsIgsgASgCFCIrQQF0rCIUfiACNAIAIgMgATQCGCIGfnwgAigCCCIsrCINIAE0AhAiB358IAIoAgwiLawiECABKAIMIi5BAXSsIhV+fCACKAIQIi+sIhEgATQCCCIIfnwgAigCFCIwrCIWIAEoAgQiMUEBdKwiF358IAIoAhgiMqwiICABNAIAIgl+fCACKAIcIjNBE2ysIgwgASgCJCI0QQF0rCIYfnwgAigCICI1QRNsrCIEIAE0AiAiCn58IAIoAiQiAkETbKwiBSABKAIcIgFBAXSsIhl+fCAHIAt+IAMgK6wiGn58IA0gLqwiG358IAggEH58IBEgMawiHH58IAkgFn58IDJBE2ysIg4gNKwiHX58IAogDH58IAQgAawiHn58IAUgBn58IAsgFX4gAyAHfnwgCCANfnwgECAXfnwgCSARfnwgMEETbKwiHyAYfnwgCiAOfnwgDCAZfnwgBCAGfnwgBSAUfnwiIkKAgIAQfCIjQhqHfCIkQoCAgAh8IiVCGYd8IhIgEkKAgIAQfCITQoCAgOAPg30+AhggACALIBd+IAMgCH58IAkgDX58IC1BE2ysIg8gGH58IAogL0ETbKwiEn58IBkgH358IAYgDn58IAwgFH58IAQgB358IAUgFX58IAkgC34gAyAcfnwgLEETbKwiISAdfnwgCiAPfnwgEiAefnwgBiAffnwgDiAafnwgByAMfnwgBCAbfnwgBSAIfnwgKkETbKwgGH4gAyAJfnwgCiAhfnwgDyAZfnwgBiASfnwgFCAffnwgByAOfnwgDCAVfnwgBCAIfnwgBSAXfnwiIUKAgIAQfCImQhqHfCInQoCAgAh8IihCGYd8Ig8gD0KAgIAQfCIpQoCAgOAPg30+AgggACAGIAt+IAMgHn58IA0gGn58IAcgEH58IBEgG358IAggFn58IBwgIH58IAkgM6wiD358IAQgHX58IAUgCn58IBNCGod8IhMgE0KAgIAIfCITQoCAgPAPg30+AhwgACAIIAt+IAMgG358IA0gHH58IAkgEH58IBIgHX58IAogH358IA4gHn58IAYgDH58IAQgGn58IAUgB358IClCGod8IgQgBEKAgIAIfCIEQoCAgPAPg30+AgwgACALIBl+IAMgCn58IAYgDX58IBAgFH58IAcgEX58IBUgFn58IAggIH58IA8gF358IAkgNawiDH58IAUgGH58IBNCGYd8IgUgBUKAgIAQfCIFQoCAgOAPg30+AiAgACAkICVCgICA8A+DfSAiICNCgICAYIN9IARCGYd8IgRCgICAEHwiDkIaiHw+AhQgACAEIA5CgICA4A+DfT4CECAAIAogC34gAyAdfnwgDSAefnwgBiAQfnwgESAafnwgByAWfnwgGyAgfnwgCCAPfnwgDCAcfnwgCSACrH58IAVCGod8IgMgA0KAgIAIfCIDQoCAgPAPg30+AiQgACAnIChCgICA8A+DfSAhICZCgICAYIN9IANCGYdCE358IgNCgICAEHwiBkIaiHw+AgQgACADIAZCgICA4A+DfT4CAAvLBgIbfgd/IAAgASgCDCIdQQF0rCIHIB2sIhN+IAEoAhAiIKwiBiABKAIIIiFBAXSsIgt+fCABKAIUIh1BAXSsIgggASgCBCIiQQF0rCICfnwgASgCGCIfrCIJIAEoAgAiI0EBdKwiBX58IAEoAiAiHkETbKwiAyAerCIQfnwgASgCJCIeQSZsrCIEIAEoAhwiAUEBdKwiFH58IAIgBn4gCyATfnwgHawiESAFfnwgAyAUfnwgBCAJfnwgAiAHfiAhrCIOIA5+fCAFIAZ+fCABQSZsrCIPIAGsIhV+fCADIB9BAXSsfnwgBCAIfnwiF0KAgIAQfCIYQhqHfCIZQoCAgAh8IhpCGYd8IgogCkKAgIAQfCIMQoCAgOAPg30+AhggACAFIA5+IAIgIqwiDX58IB9BE2ysIgogCX58IAggD358IAMgIEEBdKwiFn58IAQgB358IAggCn4gBSANfnwgBiAPfnwgAyAHfnwgBCAOfnwgHUEmbKwgEX4gI6wiDSANfnwgCiAWfnwgByAP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ACAAMQACQhCGhAvsAQESfyACKAIEIQMgASgCBCEEIAIoAgghBSABKAIIIQYgAigCDCEHIAEoAgwhCCACKAIQIQkgASgCECEKIAIoAhQhCyABKAIUIQwgAigCGCENIAEoAhghDiACKAIcIQ8gASgCHCEQIAIoAiAhESABKAIgIRIgAigCJCETIAEoAiQhFCAAIAEoAgAgAigCAGs2AgAgACAUIBNrNgIkIAAgEiARazYCICAAIBAgD2s2AhwgACAOIA1rNgIYIAAgDCALazYCFCAAIAogCWs2AhAgACAIIAdrNgIMIAAgBiAFazYCCCAAIAQgA2s2AgQL7AEBEn8gAigCBCEDIAEoAgQhBCACKAIIIQUgASgCCCEGIAIoAgwhByABKAIMIQggAigCECEJIAEoAhAhCiACKAIUIQsgASgCFCEMIAIoAhghDSABKAIYIQ4gAigCHCEPIAEoAhwhECACKAIgIREgASgCICESIAIoAiQhEyABKAIkIRQgACACKAIAIAEoAgBqNgIAIAAgEyAUajYCJCAAIBEgEmo2AiAgACAPIBBqNgIcIAAgDSAOajYCGCAAIAsgDGo2AhQgACAJIApqNgIQIAAgByAIajYCDCAAIAUgBmo2AgggACADIARqNgIECyUAA0AgAkEASgRAIAAgAkEBayICaiABOgAAIAFBCHUhAQwBCwsLMwEBfyABQQAgAUEAShshAQNAIAEgA0ZFBEAgACAAEBQgA0EBaiEDDAELCyAAIAAgAhAECxIAIABBATYCACAAQQRqQSQQFgtGAQR+IAEpAgghAiABKQIQIQMgASkCGCEEIAEpAgAhBSAAIAEpAiA3AiAgACAENwIYIAAgAzcCECAAIAI3AgggACAFNwIAC68CARN/IAEoAgQhDCAAKAIEIQMgASgCCCENIAAoAgghBCABKAIMIQ4gACgCDCEFIAEoAhAhDyAAKAIQIQYgASgCFCEQIAAoAhQhByABKAIYIREgACgCGCEIIAEoAhwhEiAAKAIcIQkgASgCICETIAAoAiAhCiABKAIkIRQgACgCJCELIABBACACayICIAAoAgAiFSABKAIAc3EgFXM2AgAgACALIAsgFHMgAnFzNgIkIAAgCiAKIBNzIAJxczYCICAAIAkgCSAScyACcXM2AhwgACAIIAggEXMgAnFzNgIYIAAgByAHIBBz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IAVqLQAAQX9zciEGIAVBAWshBQwBCwsgBkH/AXFBAWtB7AEgAi0AACIFa3FBCHYgBSAHQQd2cnJBf3NBAXELBH8gA0HQAmogAhAnIANBoAJqIANB0AJqEAMgA0HwAWoQCyADQfABaiADQfABaiADQaACahAHIANBkAFqIANB8AFqEAMgA0HAAWoQCyADQcABaiADQcABaiADQaACahAIIANB4ABqIANBwAFqEAMgA0EwakHACCADQZABahACIANBMGogA0EwahAYIANBMGogA0EwaiADQeAAahAHIAMgA0EwaiADQeAAahACIANBgANqEAsgA0GwA2ogA0GAA2ogAxAkIQUgBCADQbADaiADQcABahACIARBKGoiAiADQbADaiAEEAIgAiACIANBMGoQAiAEIAQgA0HQAmoQAiAEIAQgBBAIIAQgBBAeIAIgA0HwAWogAhACIARB0ABqEAsgBEH4AGoiBiAEIAIQAkEAIAYQIUEBIAVrciACECJyawVBfwshAiADQeADaiQAIAJFCwRAQQAhAgNAIAJBIEcEQCAAIAJqIAEgAmotAAA6AAAgAkEBaiECDAELCyAAIAAtAB9B/wBxOgAfIARBoAFqIQMjAEHAH2siASQAIAFBoAFqIAQQECABQcgbaiAEEB8gAUHoEmogAUHIG2oQDiABQcACaiICIAFB6BJqEBAgAUGoGmogBCACEBUgAUHIEWogAUGoGmoQDiABQeADaiABQcgRahAQIAFBiBlqIAFB6BJqEB8gAUGoEGogAUGIGWoQDiABQYAFaiICIAFBqBBqEBAgAUHoF2ogBCACEBUgAUGID2ogAUHoF2oQDiABQaAGaiABQYgPahAQIAFByBZqIAFByBFqEB8gAUHoDWogAUHIFmoQDiABQcAHaiICIAFB6A1qEBAgAUGoFWogBCACEBUgAUHIDGogAUGoFWoQDiABQeAIaiABQcgMahAQIAFBiBRqIAFBqBBqEB8gAUGoC2ogAUGIFGoQDiABQYAKaiABQagLahAQQQAhBUEAIQIDQCACQSBGBEBBACECA0AgAkE/RwRAIAFBgB9qIAJqIgYgBi0AACAFaiIFIAVBGHRBgICAQGsiBUEYdUHwAXFrOgAAIAJBAWohAiAFQRx1IQUMAQsLIAEgAS0Avx8gBWo6AL8fIAMQJSADQShqEAsgA0HQAGoQCyADQfgAahAlQT8hAgNAIAIEQCABIAFBoAFqIAFBgB9qIAJqLAAAEC8gAUHgHWogAyABEBUgAUHoHGogAUHgHWoQICABQeAdaiABQegcahAXIAFB6BxqIAFB4B1qECAgAUHgHWogAUHoHGoQFyABQegcaiABQeAdahAgIAFB4B1qIAFB6BxqEBcgAUHoHGogAUHgHWoQICABQeAdaiABQegcahAXIAMgAUHgHWoQDiACQQFrIQIMAQsLIAEgAUGgAWogASwAgB8QLyABQeAdaiADIAEQFSADIAFB4B1qEA4gAUHAH2okAAUgAkEBdCIGIAFBgB9qaiAAIAJqLQAAIgdBD3E6AAAgAUGAH2ogBkEBcmogB0EEdjoAACACQQFqIQIMAQsLIAAgBEGgAWoQLSAAEBkaCyAEQcACaiQAC7YGAQR/IwBBoAJrIgUkACAFQfABaiACEAMgBUHwAWogBUHwAWogAhACIAAgBUHwAWoQAyAAIAAgAhACIAAgACABEAIjAEGQAWsiAyQAIANB4ABqIAAiBhADIANBMGogA0HgAGoQAyADQTBqIANBMGoQAyADQTBqIAYgA0EwahACIANB4ABqIANB4ABqIANBMGoQAiADQeAAaiADQeAAahADIANB4ABqIANBMGogA0HgAGoQAiADQTBqIANB4ABqEANBASEEA0AgBEEFRwRAIARBAWohBCADQTBqIANBMGoQAwwBCwsgA0HgAGogA0EwaiADQeAAahACIANBMGogA0HgAGoQA0EBIQQDQCAEQQpHBEAgBEEBaiEEIANBMGogA0EwahADDAELCyADQTBqIANBMGogA0HgAGoQAiADIANBMGoQA0EBIQQDQCAEQRRHBEAgBEEBaiEEIAMgAxADDAELCyADQTBqIAMgA0EwahACQQEhBANAIARBC0cEQCAEQQFqIQQgA0EwaiADQTBqEAMMAQsLIANB4ABqIANBMGogA0HgAGoQAiADQTBqIANB4ABqEANBASEEA0AgBEEyRwRAIARBAWohBCADQTBqIANBMGoQAwwBCwsgA0EwaiADQTBqIANB4ABqEAIgAyADQTBqEANBASEEA0AgBEHkAEcEQCAEQQFqIQQgAyADEAMMAQsLIANBMGogAyADQTBqEAJBASEEA0AgBEEzRwRAIARBAWohBCADQTBqIANBMGoQAwwBCwsgA0HgAGogA0EwaiADQeAAahACIANB4ABqIANB4ABqEAMgA0HgAGogA0HgAGoQAyAAIANB4ABqIAYQAiADQZABaiQAIAYgBiAFQfABahACIAYgBiABEAIgBUHAAWogBhADIAVBwAFqIAVBwAFqIAIQAiAFQZABaiAFQcABaiABEAcgBUHgAGogBUHAAWogARAIIAVBMGogAUHwCBACIAVBMGogBUHAAWogBUEwahAIIAVBkAFqECIhASAFQeAAahAiIQAgBUEwahAiIQIgBSAGQfAIEAIgBiAFIAAgAnIQDSAGIAYQHiAFQaACaiQAIAAgAXILCAAgAEEoEBYL+gUBCn8jAEEwayICJAAgAiABKAIgIgMgASgCHCIEIAEoAhgiBSABKAIUIgYgASgCECIHIAEoAgwiCCABKAIIIgkgASgCBCIKIAEoAgAiCyABKAIkIgFBE2xBgICACGpBGXZqQRp1akEZdWpBGnVqQRl1akEadWpBGXVqQRp1akEZdWpBGnUgAWpBGXVBE2wgC2oiC0H///8fcTYCACACIAogC0EadWoiCkH///8PcTYCBCACIAkgCkEZdWoiCUH///8fcTYCCCACIAggCUEadWoiCEH///8PcTYCDCACIAcgCEEZdWoiB0H///8fcTYCECACIAYgB0EadWoiBkH///8PcTYCFCACIAUgBkEZdWoiBUH///8fcTYCGCACIAQgBUEadWoiBEH///8PcTYCHCACIAMgBEEZdWoiA0H///8fcTYCICACIAEgA0EadWpB////D3E2AiQgACACKAIAIgE6AAAgACABQRB2OgACIAAgAUEIdjoAASAAIAIoAgQiA0EOdjoABSAAIANBBnY6AAQgACADQQJ0IAFBGHZyOgADIAAgAigCCCIBQQ12OgAIIAAgAUEFdjoAByAAIAFBA3QgA0EWdnI6AAYgACACKAIMIgNBC3Y6AAsgACADQQN2OgAKIAAgA0EFdCABQRV2cjoACSAAIAIoAhAiAUESdjoADyAAIAFBCnY6AA4gACABQQJ2OgANIAAgAUEGdCADQRN2cjoADCAAIAIoAhQiAToAECAAIAFBEHY6ABIgACABQQh2OgARIAAgAigCGCIDQQ92OgAVIAAgA0EHdjoAFCAAIANBAXQgAUEYdnI6ABMgACACKAIcIgFBDXY6ABggACABQQV2OgAXIAAgAUEDdCADQRd2cjoAFiAAIAIoAiAiA0EMdjoAGyAAIANBBHY6ABogACADQQR0IAFBFXZyOgAZIAAgAigCJCIBQRJ2OgAfIAAgAUEKdjoAHiAAIAFBAnY6AB0gACABQQZ0IANBFHZyOgAcIAJBMGokAAvCAwEMfiABNQAAIQQgAUEEahAGIQUgAUEHahAGIQYgAUEKahAGIQIgAUENahAGIQcgATUAECEDIAFBFGoQBiEIIAFBF2oQBiEJIAFBGmoQBiEKIAFBHWoQBiELIAAgAkIDhiICIAJCgICACHwiAkKAgIDwD4N9IAZCBYYgBUIGhiIFQoCAgAh8IgZCGYd8IgxCgICAEHwiDUIaiHw+AgwgACAMIA1CgICA4A+DfT4CCCAAIAMgA0KAgIAIfCIDQoCAgPAPg30gB0IChiACQhmHfCICQoCAgBB8IgdCGoh8PgIUIAAgAiAHQoCAgOAPg30+AhAgACAIQgeGIANCGYd8IgMgA0KAgIAQfCIDQoCAgOAPg30+AhggACAJQgWGIgIgAkKAgIAIfCICQoCAgPAPg30gA0IaiHw+AhwgACAKQgSGIAJCGYd8IgMgA0KAgIAQfCIDQoCAgOAPg30+AiAgACALQgKGQvz//w+DIgIgAkKAgIAIfCICQoCAgBCDfSADQhqIfD4CJCAAIAUgBkKAgIDwD4N9IAQgAkIZiEITfnwiA0KAgIAQfCIEQhqIfD4CBCAAIAMgBEKAgIDgD4N9PgIACwMAAQu7BgEHfyMAQSBrIgckACMAQSBrIgUkACAFQR1qQQBBARAJIAVBHmpBAUECEAkgBUGvCCkAADcADyAFQagIKQMANwMIIAVBoAgpAwA3AwAgBSAFQRQgBUEdahAwIwBBQGoiBiQAIwBBoAZrIgQkACAEQdAEahAdIARB0ANqQYABEBYgBEHQBGogBEHQA2pCgAEQBSAEQdAEaiABIAKsEAUgBEEAOwHOA0ECIQIgBEHOA2pBwABBAhAJIARB0ARqIARBzgNqQgIQBSAEQQA6AM0DIARBzQNqQQBBARAJIARB0ARqIARBzQNqQgEQBSAEQdAEaiAFQhcQBSAEQc0DakEXQQEQCSAEQdAEaiAEQc0DakIBEAUgBEHQBGogBEGAA2oQGyAEQdAEahAdIARB0ARqIARBgANqQsAAEAUgBEHNA2pBAUEBEAkgBEHQBGogBEHNA2pCARAFIARB0ARqIAVCFxAFIARBzQNqQRdBARAJIARB0ARqIARBzQNqQgEQBSAEQdAEaiAEQcACahAbIARBgAFqQcABEBYgBEFAayAEQcACakHAABATGgNAIAJBAkYEQCAGIARBQGtBwAAQExogBEHQBGpB0AEQEiAEQUBrQYACEBIgBEGgBmokAAUgBEHQBGoQHSAEQYADaiEIIARBQGsgAkEGdGoiCUGAAWshCkEAIQEDQCABQcAARwRAIAEgBGogASAKai0AACABIAhqLQAAczoAACABQQFqIQEMAQsLIARB0ARqIARCwAAQBSAEQc0DaiACQQEQCSAEQdAEaiAEQc0DakIBEAUgBEHQBGogBUIXEAUgBEHNA2pBF0EBEAkgBEHQBGogBEHNA2pCARAFIARB0ARqIAlBQGoQGyACQQFqIQIMAQsLIwBBgAdrIgEkACABQdAGaiAGECcgAUGgBmogBkEgahAnIAFBwAJqIAFB0AZqECwgAUGgAWogAUGgBmoQLCABQYAFaiABQaABahAQIAFB4ANqIAFBwAJqIAFBgAVqEBUgASABQeADahAOIAcgARAtIAFBgAdqJAAgBkHAABASIAZBQGskACAFQSBqJAAgACADIAcQIyAHQSAQEiAHQSBqJAALRwEDfwNAIAEgAkcEQCMAQRBrIgMkACADQQA6AA9B8BEgA0EPakEAEAAhBCADQRBqJAAgACACaiAEOgAAIAJBAWohAgwBCwsLlwECAX4CfyACQQN2IQRBACECA0AgAiAERwRAIAAgAkEDdCIFaiABIAVqKQMAIgNCKIZCgICAgICAwP8AgyADQjiGhCADQhiGQoCAgICA4D+DIANCCIZCgICAgPAfg4SEIANCCIhCgICA+A+DIANCGIhCgID8B4OEIANCKIhCgP4DgyADQjiIhISENwAAIAJBAWohAgwBCwsLnQQBAn8jAEGgBWsiAiQAIAJBkARqEAsgAkHgA2ogARADIAJB4ANqQfAIIAJB4ANqEAIgAkHwAWogAkHgA2ogAkGQBGoQCCACQfABaiACQfABakGgChACIAJB8ARqEAsgAkHwBGogAkHwBGoQGCACQbADaiACQeADakHACBAIIAJBwAFqIAJB4ANqQcAIEAIgAkHAAWogAkHwBGogAkHAAWoQByACQcABaiACQcABaiACQbADahACIAJBgANqIAJB8AFqIAJBwAFqECQhAyACQdACaiACQYADaiABEAIgAkHQAmogAkHQAmoQHiACQdACaiACQdACahAYIAJBgANqIAJB0AJqQQEgA2siARANIAJB8ARqIAJB4ANqIAEQDSACQcAEaiACQeADaiACQZAEahAHIAJBwARqIAJBwARqIAJB8ARqEAIgAkHABGogAkHABGpB0AoQAiACQcAEaiACQcAEaiACQcABahAHIAJBkAFqIAJBgANqIAJBgANqEAggAkGQAWogAkGQAWogAkHAAWoQAiACQeAAaiACQcAEakGACxACIAJBoAJqIAJBgANqEAMgAkEwaiACQZAEaiACQaACahAHIAIgAkGQBGogAkGgAmoQCCAAIAJBkAFqIAIQAiAAQShqIAJBMGogAkHgAGoQAiAAQdAAaiACQeAAaiACEAIgAEH4AGogAkGQAWogAkEwahACIAJBoAVqJAAL2gMBBH8jAEHgBmsiAiQAIAJB0AJqIAFB0ABqIgUgAUEoaiIEEAggAiAFIAQQByACQdACaiACQdACaiACEAIgAkGgAmogASAEEAIgAkHwAWogAkGgAmoQAyACQfABaiACQdACaiACQfABahACIAJB4ANqEAsgAkHwBGogAkHgA2ogAkHwAWoQJBogAkGwBmogAkHwBGogAkHQAmoQAiACQYAGaiACQfAEaiACQaACahACIAJBMGogAkGwBmogAkGABmoQAiACQTBqIAJBMGogAUH4AGoiAxACIAJBwARqIAFB8AgQAiACQZAEaiAEQfAIEAIgAkGgBWogAkGwBmpB8AkQAiACQYADaiADIAJBMGoQAiACQYADahAhIQMgAkHAAWogARAMIAJBkAFqIAQQDCACQdAFaiACQYAGahAMIAJBwAFqIAJBkARqIAMQDSACQZABaiACQcAEaiADEA0gAkHQBWogAkGgBWogAxANIAJB4ABqIAJBwAFqIAJBMGoQAiACQZABaiACQZABaiACQeAAahAhEC4gAkGwA2ogBSACQZABahAHIAJBsANqIAJB0AVqIAJBsANqEAIgAkGwA2ogAkGwA2oQHiAAIAJBsANqECYgAkHgBmokAAsoAQF/IwBBMGsiAyQAIAMgARAYIAAgARAMIAAgAyACEA0gA0EwaiQAC4ACAQJ/IwBBoAFrIgMk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");var HEAP8,HEAP16,HEAP32,HEAPU8,HEAPU16,HEAPU32,HEAPF32,HEAPF64;var wasmMemory,buffer,wasmTable;function updateGlobalBufferAndViews(b){buffer=b;HEAP8=new Int8Array(b);HEAP16=new Int16Array(b);HEAP32=new Int32Array(b);HEAPU8=new Uint8Array(b);HEAPU16=new Uint16Array(b);HEAPU32=new Uint32Array(b);HEAPF32=new Float32Array(b);HEAPF64=new Float64Array(b)}var ASM_CONSTS={2288:function(){return Module.getRandomValue()},2324:function(){if(Module.getRandomValue===undefined){try{var window_="object"===typeof window?window:self;var crypto_=typeof window_.crypto!=="undefined"?window_.crypto:window_.msCrypto;var randomValuesStandard=function(){var buf=new Uint32Array(1);crypto_.getRandomValues(buf);return buf[0]>>>0};randomValuesStandard();Module.getRandomValue=randomValuesStandard}catch(e){try{var crypto=require("crypto");var randomValueNodeJS=function(){var buf=crypto["randomBytes"](4);return(buf[0]<<24|buf[1]<<16|buf[2]<<8|buf[3])>>>0};randomValueNodeJS();Module.getRandomValue=randomValueNodeJS}catch(e){throw"No secure random number generator found"}}}}};var readAsmConstArgsArray=[];function readAsmConstArgs(sigPtr,buf){readAsmConstArgsArray.length=0;var ch;buf>>=2;while(ch=HEAPU8[sigPtr++]){var double=ch<105;if(double&&buf&1)buf++;readAsmConstArgsArray.push(double?HEAPF64[buf++>>1]:HEAP32[buf]);++buf}return readAsmConstArgsArray}function _emscripten_asm_const_int(code,sigPtr,argbuf){var args=readAsmConstArgs(sigPtr,argbuf);return ASM_CONSTS[code].apply(null,args)}var asmLibraryArg={"a":_emscripten_asm_const_int};function initRuntime(asm){asm["c"]()}var imports={"a":asmLibraryArg};var _ecc_memzero,_ecc_randombytes,_ecc_oprf_ristretto255_sha512_Evaluate,_ecc_oprf_ristretto255_sha512_BlindWithScalar,_ecc_oprf_ristretto255_sha512_Blind,_ecc_oprf_ristretto255_sha512_Finalize;WebAssembly.instantiate(Module["wasm"],imports).then(function(output){var asm=output.instance.exports;_ecc_memzero=asm["d"];_ecc_randombytes=asm["e"];_ecc_oprf_ristretto255_sha512_Evaluate=asm["g"];_ecc_oprf_ristretto255_sha512_BlindWithScalar=asm["h"];_ecc_oprf_ristretto255_sha512_Blind=asm["i"];_ecc_oprf_ristretto255_sha512_Finalize=asm["j"];wasmTable=asm["f"];wasmMemory=asm["b"];updateGlobalBufferAndViews(wasmMemory.buffer);initRuntime(asm);ready()});function arraycopy(src,srcPos,dest,destPos,length){dest.set(src.subarray(srcPos,srcPos+length),destPos)}function mput(src,pos,length){arraycopy(src,0,HEAPU8,pos,length);return pos}function mget(pos,dest,length){arraycopy(HEAPU8,pos,dest,0,length)}function mzero(length){_ecc_memzero(0,length)}Module.ecc_randombytes=((buf,n)=>{const pBuf=0;_ecc_randombytes(pBuf,n);mget(pBuf,buf,n);mzero(n)});Module.ecc_oprf_ristretto255_sha512_Evaluate=((evaluatedElement,skS,blindedElement)=>{const pSkS=mput(skS,0,32);const pBlindedElement=mput(blindedElement,pSkS+32,32);const pEvaluatedElement=pBlindedElement+32;_ecc_oprf_ristretto255_sha512_Evaluate(pEvaluatedElement,pSkS,pBlindedElement);mget(pEvaluatedElement,evaluatedElement,32);mzero(32+32+32)});Module.ecc_oprf_ristretto255_sha512_BlindWithScalar=((blindedElement,input,input_len,blind)=>{const pInput=mput(input,0,input_len);const pBlind=mput(blind,pInput+input_len,32);const pBlindedElement=pBlind+32;_ecc_oprf_ristretto255_sha512_BlindWithScalar(pBlindedElement,pInput,input_len,pBlind);mget(pBlindedElement,blindedElement,32);mzero(input_len+32+32)});Module.ecc_oprf_ristretto255_sha512_Blind=((blindedElement,blind,input,input_len)=>{const pInput=mput(input,0,input_len);const pBlindedElement=pInput+input_len;const pBlind=pBlindedElement+32;_ecc_oprf_ristretto255_sha512_Blind(pBlindedElement,pBlind,pInput,input_len);mget(pBlindedElement,blindedElement,32);mget(pBlind,blind,32);mzero(input_len+32+32)});Module.ecc_oprf_ristretto255_sha512_Finalize=((output,input,input_len,blind,evaluatedElement,mode)=>{const pInput=mput(input,0,input_len);const pBlind=mput(blind,pInput+input_len,32);const pEvaluatedElement=mput(evaluatedElement,pBlind+32,32);const pOutput=pEvaluatedElement+32;_ecc_oprf_ristretto255_sha512_Finalize(pOutput,pInput,input_len,pBlind,pEvaluatedElement,mode);mget(pOutput,output,64);mzero(input_len+32+32+64)});


  return liboprf_module.ready
}
export default liboprf_module;