// BIP39 Test Cases from Libdogecoin

package test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/dogeorg/doge/bip39"
)

var LibdogecoinTests = map[string][][]string{
	// English with passphrase (iancoleman.io/bip39)
	"english": {
		{
			"chief prevent advice search broccoli dish pride grow evidence bicycle cushion lady",
			"31113f96716b7d5b8d58a49c5e1f6d6300ff307b35eef3cecfdb97869e514ad330f0a7dcec4ed2feeebf8d2267ebfefeb149df84642ca091befd25ea15d36076",
			"TREZOR",
		},
		{
			"engine link summer museum gift sphere half void where long copper mandate push valve enhance",
			"7de0820caafcfc0695724ed19c3f35531c1f290650a0b39c053e67175979ed05dfedc824dcf9ac38cbc014fa86a2836c5b5e3b9ab1b9f0f84a76c492a04665b0",
			"TREZOR",
		},
		{
			"outside clarify pizza swim section menu current kite step nothing actor smoke swarm chronic ritual vanish cinnamon cotton",
			"fffa2ea3c80653436c24f629581a4b3daf9843fab6f524f642aa71ffbeab7b6ce7aaa1ea03fb3686eb3b661bd2ee80bc5c42b3e94d91d40bd89a3bf9319428a2",
			"TREZOR",
		},
		{
			"turtle shock bar amount damp ostrich door quick smart woman tell hobby mansion duty common calm curious audit exist napkin verb",
			"706f79690efe53f124b30caf062603229735dbee0431aa7832a047ef6456a045c33d7274ef8ed97fc23bd1aaf0b02a3d50d91196ae9a9a005fbf90e76ddbce08",
			"TREZOR",
		},
		{
			"depth artist same second negative vehicle van owner strong catch wreck salute fall lady nest sense champion foil switch become mule notable fame aerobic",
			"65b6c6b1e71980836b3c98ca9fd879d32e1d225c7095e3c17e68ea6daf2ea856b6e04f05e0d4a627b8d82975319b83e0dff0ab817d8e25646287f51b06b44af4",
			"TREZOR",
		},
	},
	"japanese": {
		{
			"ねんいり　でんち　くうぼ　そよかぜ　ななおし　さかな　るいせき　なのか　こえる　たいら　ねんまつ　くのう",
			"5b503adf88021a6438989c35647458d531cac635f0b5783990db2934bf5216ab6df09ec0cf81221c3bbecfebdf1bb7ea45c20cf68a4536cfbd745fe1e0bcd10a",
			"",
		},
		{
			"りかい　めんどう　はそん　せつび　はにかむ　あんぜん　こちょう　けんない　つたえる　しゃれい　せんか　えいぶん　ゆたか　そらまめ　たまる",
			"be5a9e28d6963f510b25e68e080bc937c0a006dc3e703b324d6296f519ed9dc6efb92958690ea03b2e10a22946abdf9285cb824bcfb737cf08e99d031e414816",
			"",
		},
		{
			"なふだ　のみもの　えんちょう　にんそう　ふっかつ　はろうぃん　つわもの　てんかい　さんみ　うったえる　ともる　ばかり　しひょう　すうせん　せこう　さつまいも　たぼう　すろっと",
			"e7dde84dad6e16e4d7dbd89d8f428e97d8501fa4e8ca8debbfdc5790134d405688e750847e883c2b9eceaab532029e78125c184e2158e640e313966154b89863",
			"",
		},
		{
			"ぐんたい　てぬき　ひさしぶり　ていさつ　しまう　ひりつ　ひやす　ゆちゃく　りれき　きのう　たおす　ぬぐいとる　しむける　ねんりょう　むりょう　とつにゅう　おもたい　せまい　がっこう　ぜんぶ　おもたい",
			"ffbf25e2b5cee4838ae30694a86f2bc8e867641adececdde182e164908632a9966e3733f5e28849434ff9a898fe3a2ed6d05c25cd7654edd9d625a7a231b211f",
			"",
		},
		{
			"ぜっく　へらす　くのう　けんちく　えんげき　でっぱ　しあわせ　せっかく　いれい　こんかい　ていおん　ぞんび　せんえい　おうたい　りせい　たんにん　こうすい　ゆれる　てんさい　いりょう　すはだ　ばんぐみ　うつる　ほいく",
			"b68f2864826537e17f61bc5fe6d142d711b853f4aedf033b5d6e38d2a554fdbac1143287cfb2bfd650b89472692c5c1fc0b25d491846004fd01be8f4ab5c7439",
			"",
		},
	},
	"spanish": {
		{
			"suelo tribu filtro probar mortal limón risa pueblo plaza oreja tutor mambo",
			"356b6fc9e52ac2b872d9f56048f58346ff1526c014dd5019e64f45f4fee43873f570a1c181ddd81bfa91dd442da13282eb031833efb50554f387446e3c10c455",
			"",
		},
		{
			"tono cordón llave cetro negar fachada impar mar jabón azufre sacar aumento tropa lazo sartén",
			"87587a1d17cb36470b6d372d8cf32c1897639b8884ab5ef3fc5b05eb35f7cccdc463836bd8b6112f36020330df9c4e517cedbfdb282782a1323ffbd0517e360d",
			"",
		},
		{
			"ecuador sello justo peine aporte mando estar tabla viral traer vacuna pitón código ebrio camello adoptar farmacia niño",
			"666268e83f039eff8ce27a215dfd9debcd3c3fe15347c130f36d87ec7bb99a26422617e1157c08c2a2bd4c0dfcddeaf497482095dd1f09870462971bddf2490f",
			"",
		},
		{
			"límite fábrica juntar lástima loción poeta botín cuerda rechazo niñez ser asesor salón bonsái folleto capucha mercado barco ébano reacción agregar",
			"1be238fda08ecc34e14e71066c4e6bcb49db52191663e114d64a2c1eaa1a89aaeb4cd6789800ff29d71a1ced979dfaa21daedcf5818bb3afc0ad4255153e554a",
			"",
		},
		{
			"bocina gajo pausa empeño evadir rotar sala tórax latir inmenso riqueza brazo empate aval urna astuto agregar masivo divino justo vajilla ligero ocre filete",
			"9b5a8911d37bb23f72a17af0fe8e98fe97132e81b239478ee1ae0543dfe9852fe1db5bc9f172a421c3656093a6c07b5db0a72d55daefc3d979f8f27d5008f592",
			"",
		},
	},
	"chinese_simplified": {

		{
			"船 弓 十 凡 抽 渠 隆 项 牵 追 跟 非",
			"03eb61243f0459ffe45c435b04adb5f0b681b08326c61560899c4b1b13c3cbb8aee8f66909d175fd4fe0b59b5f0d42a2efb4a48de1515adbfc5be1e35bc11b7a",
			"",
		},
		{
			"湾 砖 摆 续 粮 破 塑 精 值 藏 食 飞 换 摊 缺",
			"7b4580f94058c8edee646bbc42f85b5e43f0ec7c70747443601bdc03d1a7fcbb47701cd8f277f1b75868b5fe01d8ba8c8bfa6da46e2f9feea27ebb8b42087f0c",
			"",
		},
		{
			"林 情 钉 纳 置 渡 沿 浅 算 开 或 睛 钻 斤 武 迁 独 物",
			"8bfd7485d9e1d26f2a8a500dd93a13e720f00f499621c2d7300dc846ea972366e9649505b7ec6f2e81eb282582e4ff9c3ce462a776397fd3d0b6ef2bb38ea394",
			"",
		},
		{
			"致 纤 家 言 乎 又 饿 残 辛 经 在 同 刘 寻 版 莫 胎 月 孩 抽 本",
			"58abf72e35b6b8fd27f45295c08d419545b7bae6cee4c4896a9469dfb7c2e85801e7acdaf053f545c3cc9783245d6b3fb08028e8ba50fe3c3ec74217b20fcd44",
			"",
		},
		{
			"团 样 洛 此 相 乌 郑 效 成 饱 浇 持 贡 齿 村 弯 低 欧 暗 锦 泥 异 野 仪",
			"17af4b558add20c219d9aeef74d8dfef2c2884d2e9ccb4f7e3b0c229414447fcea9695b8488c82800eb81072e868cca37a95ca2ef8783e4a1eda757e6d64e9ff",
			"",
		},
	},
	"chinese_traditional": {
		{
			"船 弓 十 凡 抽 渠 隆 項 牽 追 跟 非",
			"339754cbf29d76b22974d574846ab5673364d55392e40135dbecd0604b2dcb9c495ec8428f94be2c30ed5a7d503de8410b700d73121c13126f0ad79b3e80a184",
			"",
		},
		{
			"萊 搭 準 幸 邁 線 密 羽 搜 淨 鬼 蔥 端 獄 義",
			"481f18790dc36d00cc44cbf2b78b134304c14d02a9978ca6ed46d4480050f6a3f734402acfc60f43e42acb5809ad5a72c84b773c7ea826dc847e28bbd2d74ebb",
			"",
		},
		{
			"東 惡 伸 原 呆 落 喝 滲 貯 裁 久 抹 提 或 雅 為 傾 摩",
			"8dc2b209ced582b1521d0ebca87feeecba7ed8dad3ba926887045c8e82861daf2e4985ecbcd35df01e7d1ecf8d3e61695543738fb2a9324551375c689db37c9c",
			"",
		},
		{
			"育 富 熟 疊 值 籍 直 牲 躺 權 凡 彈 承 涼 期 盡 欲 社 華 禁 疆",
			"06dfb8571fc57cee1cc2d2e411a0f07b5952860aa92b38e46c9305a3044d2647482d87d4b5aafc587863fa5569a303bb2839e13b8e3401b1ff3c0d6645918169",
			"",
		},
		{
			"請 煩 岸 孟 徹 食 歪 塘 租 產 青 賽 任 態 呼 驗 對 格 又 某 迎 郎 陰 堡",
			"a6c984b2df85b28737961644725d88cf829fb109cf658fcb5b487ccc46c634f4b10cff1808c21b9707078ec0936da799660fb5e93ded92aa8425b36994288914",
			"",
		},
	},
	"french": {
		{
			"bureau créature clairon cravate duperie wagon chance naufrage soucieux xénon spécial social",
			"559c4edd65377217a6763fcd94da5a84f258d8d59c04d083d08072ada86cf8050bfadbab2ac67519f7b971ac7fdc3b34844195e4910b5c6df0747516e5642461",
			"",
		},
		{
			"niche refrain balcon élégant tangible bassin incolore pluie meilleur visqueux luxueux adverbe hélium problème jeunesse",
			"5e349ef532853110ea73006f536216da753028fffa07909e83fa9715f8c4c14cb89e14e22b958659da673003a572bf2ffc6305ef9cb17e99adfba830111aec65",
			"",
		},
		{
			"pleurer seigneur sérum daigner opter filière proverbe arbitre crémeux météore cendrier prison jupon dialogue brousse acteur larme suspect",
			"98dcf7d46ca99ad70f079a96e4a0143b51f13c7231d2699a4bd334e1cbb3361c4e30dade67be7b3f9c01b817205200cfc6b76f71dfb6c7874889a782c776702d",
			"",
		},
		{
			"négliger boussole olivier jongler boussole saboter quiétude blinder inventer éléphant douter titane surprise domicile éblouir capuche amusant hésiter exceller obstacle hommage",
			"c76e657e9d486afaca17ec1b6d1613da99625bfffb8674786d43bb9cd0f9097497b8e3bcde02fe65c80a6c12ea7eeb805ad19753a04235da8076acca39aea603",
			"",
		},
		{
			"mélange borne fictif minorer éclipse roseau caféine sirop précieux haricot durcir congeler relief serrure tarder redouter effrayer isoler électron lithium vipère salive employer associer",
			"12f59f6d1a88248e53799c99c3b1d79e53c517d2fdd0ce678053c8756e049bd7fa7e33235cdd3f2ee5828ff97cf4842bc7b313db19e80305515f7c44aa127883",
			"",
		},
	},
	"italian": {

		{
			"recluta rinomato insano pomodoro recinto mini sorpasso zotico parola sisma oliato radicale",
			"934f7e1f5ef8a213d3114b0d472d90db2553b54244b9a12b7be08b22ab3523199d2a1b45366ea3715336d4bc04db78b5edb080ca76bc43236ecc143bc1d80dae",
			"",
		},
		{
			"sinusoide eroe gemello gasdotto avvolgere etnico energia miele convegno proteso infilare gastrico etilico acqua baldo",
			"3819320a5253380f6218d084c565aef4d41990a0250cdba1da4694301cd2c1f363a6cdb735be63c70debada8c0621396a1d36045a7aa510c4a64d42881326c9e",
			"",
		},
		{
			"peloso attrito elfico sociale druido insetto amanita figurato inondato pinna aria pagina raddoppio savana valanga grande labbro scrutinio",
			"23daa08ff94cbc8a3e7025a926785c0a2fd68d95f2c770ed218897d52f2bf9d9fb20e2337c6c79b0f68ff07b99cde348198519cb6e2e7c53c617a81bcb99e993",
			"",
		},
		{
			"balcone barocco rinascita limpido scoprire pallido malgrado guadagno gruppo seccatura svuotare cratere fascia forbito alcolico gittata baraonda equatore giusto risvolto maiolica",
			"4f068bbb923656eb7d4e6f51afae5c4c5a8e5651f2be1799b34feb5cfd045f220b6cf1dfbfa774e38961551d2fda8622921a33d760b56ef63a58080fd5b0ffba",
			"",
		},
		{
			"abbinato prudente pesista zelante occasione malsano dubitare autunno ricco pallido perbene brevetto pretesto mucca roco roccia svizzera mughetto cometa impacco accadere ridicolo cavillo esteso",
			"7ae437607fb83f2edf24b8458f2580828558aeb696ef8d5b09c82106f047bc81ab325cdcd1b3d612be89fc9ae5ca4d2044f96b5234c63bffdda09eb12365d34a",
			"",
		},
	},
	"korean": {
		{
			"운반 입학 정문 장미 철도 인근 반죽 큰아들 복숭아 발달 저곳 첫째",
			"2d94c81f2a3806404ef54c07b3d028bd2930480d2dcb305ff0e9f0a45328787ac6b2b4e447bb0e085dfc416c7950889151a8a842fa27a1fccef72d17fb42102b",
			"",
		},
		{
			"기간 수시로 야간 포스터 야단 월드컵 메일 비닐 비둘기 방향 제대로 무조건 증거 합격 방해",
			"6920b40e52d0007f3e41d218fb814af3be1fafb76da33512c9b60fd4e7fce549173232fd406a797aea721660b56140c8d06df1def66621f62beb6ad58ae74395",
			"",
		},
		{
			"백두산 컬러 채널 인천 부친 검토 토요일 빛깔 기술 사나이 이렇게 구입 정부 광주 부담 평균 예약 페인트",
			"46089b89d2af2b61ec96330bae5bc5058482957f69b2c73594f111dfd77c9d890b5b2d601a5b103c81c553abed890e1dec409f164ceb3b7fec30664d644e44b5",
			"",
		},
		{
			"튼튼히 재생 성질 녹음 유럽 일곱 침대 농촌 수입 시각 설악산 여섯 성질 안경 하필 외국 하느님 조정 처음 사건 퇴근",
			"4cf73edeb76c7febc972e135321841b6a7e455e55f785fcc40f5559dadcadc065c477fef15a65080b7d18edf99da6e59a817255fa11537fff6ed0e98a8f69acb",
			"",
		},
		{
			"피망 검사 한꺼번에 객관적 계단 발달 경고 우승 제안 직장 골짜기 일회용 절약 유치원 감소 인형 그제서야 찬물 방법 몸속 여학생 잠깐 현지 큰아들",
			"642855a8f4c22bf922896fcc7279123fb0d3bd919f365a4dac0bf481314179d25bf052f09681cfbab956b7ab7844a8e98f665056ad646ad4dde0ad47d68a0b60",
			"",
		},
	},
	"czech": {
		{
			"pazneht minulost pointa stavba situace farmacie obilnice makovice koleda expedice tvrdost imunita",
			"fed95cb2957ff74b6669d6311e115eb559779c71e113206993cb6bc45494f5ad20efbf96681180a2764090ac47db72a896e20d181e3fae113943583f8466a70f",
			"",
		},
		{
			"svorka rasovna vyklopit pomsta vrstva mudrc konkurs spis kamkoliv studna krach pedagog kokos rukavice koalice",
			"5361394d4a10e0839e404f73c364fa742dca4aeee26f91be8777dfb154a12e83501a46b4d8aaaa9497efd415d675d7f8b5680f534c0e2d91aa421b8370fe2ec4",
			"",
		},
		{
			"mnohem genetika celkem podcenit glazura chirurg kostka bobr smetana srdce evoluce hejno klasika doklad mutace lentilka leckdy zarazit",
			"3b199ca5b5979ef18f70538a89229976aac3cabeb24b85d8c90a913e853e3be07d2e45864c284a10440d65ff8384ccb6637f67f498ba4a390be6c5831f7c669c",
			"",
		},
		{
			"osnova andulka petice vzdychat odsoudit zlost hravost obal rekrut sypat kupodivu bezmoc hotovost pohovor monstrum kotel rychlost rydlo nadobro bageta tuzemsko",
			"f8eb833e09e88cd51c7a9f7e15d06b6e143d2fb83a21610bc9cfb63cac4edcb4048f70861fe03e3fe474cf2deb2cb23b7372e03decc313bc8e4a91dcc959367f",
			"",
		},
		{
			"svorka aktovka penze chrup ustlat cinkot omeleta naslepo pracovat chrup volno najisto budka dosyta internet malina mikrofon disk vlevo diktovat vymezit linoleum dolar snaha",
			"45ebe3babee8dd301edce6e0208b3383ce88420aa2ee420ba0e3bdef734e1d624ad262a664caaa444d4fcc6d5ffd3c0a16ab610a32043334dd4b67e5107d679a",
			"",
		},
	},
	"portuguese": {
		{
			"recente beldade beleza lacre molinete roleta gazela comover caju trindade dedicado greve",
			"05fd0c3a7ad7abdc37cd87b67ba14c4234d9c5fe565a53b65a274a6ed93e6b3dccb19ba741e919caff04abbea8fea1ee067774228122019cf1b301a644f688ba",
			"",
		},
		{
			"simular nordeste recente gordura rabanada limoeiro predador informal esponja soja ateu fraterno bendito rabisco faixa",
			"a48adaa52c74c25cb2208e7f85fc9aea499876510ba9e11f95bae70335e1c7442bba8611bd00b1a29b48642b994c17d58568305f592b1bb0f9d47ac6ff721bfd",
			"",
		},
		{
			"canivete agora samurai perceber sinopse atalho erguido dosagem beldade jorrar drogaria abater linda enlatar cobaia uniforme desenho saliva",
			"fc0771a4daee0a05da18b8bc21f359366f671fb572db8b2c991526c296a1d03c53c0c2a6a7fc4c9c7717c1ad9e71afab425ee44a36388a138572d993e6db9d7e",
			"",
		},
		{
			"genro piscar coquetel voar ringue retalho biosfera rouco gaiola palito fera damasco insulto cerrado glicose patrono rosto tanto fungo quente disquete",
			"f3d4a0be131851a0a6d9f77356d1edfc81e19baf799460fd4ee3d976423bd7b9ec0513e437bb49fd7e65d92b991c686c3ee07dfa0f3469bd15795b1a6d068e76",
			"",
		},
		{
			"caule rotina vertente prece lousa genro focinho grampo embutido locador chumbo espumar melhor abranger cortejo sugador povoar alocar chave bolha tarraxa apesar isolado quina",
			"a1996cc0f01b82b8af10af4563bbb907a9bd82c6e16e8632fe617a5d63f2eed6f33181c8358f77ddd8f461476ac6faee548523c6512400e55341d8b0215e0351",
			"",
		},
	},
}

func TestBip39Libdogeoin(t *testing.T) {
	for lang, tests := range LibdogecoinTests {
		for tno, test := range tests {
			if len(test) != 3 {
				panic("bad test-vector")
			}
			mnemonic, seedHex, password := test[0], test[1], test[2]
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				panic(err)
			}
			if bip39.WordLists[lang] == nil {
				panic("bad lang" + lang)
			}
			words := strings.Split(mnemonic, bip39.LangSpace[lang])
			res_seed, err := bip39.SeedFromMnemonic(words, password, bip39.WordLists[lang])
			if err != nil {
				t.Errorf("SeedFromMnemonic: %v", err)
				continue
			}
			if !bytes.Equal(res_seed, seed) {
				t.Errorf("test %v:%v: incorrect seed from mnemonic: '%v' vs '%v'", lang, tno, hex.EncodeToString(res_seed), seedHex)
			}
		}
	}
}

// Test with known entropy values
var KnownEntropyTests = [][]string{
	{
		"english",
		"00000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	},
	{
		"english",
		"0000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
	},
	{
		"english",
		"000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
	},
	{
		"english",
		"00000000000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
	},
	{
		"english",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
	},
	{
		"japanese",
		"00000000000000000000000000000000",
		"あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
	},
	{
		"japanese",
		"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		"そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかめ",
	},
	{
		"japanese",
		"15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
		"うちゅう　ふそく　ひしょ　がちょう　うけもつ　めいそう　みかん　そざい　いばる　うけとる　さんま　さこつ　おうさま　ぱんつ　しひょう　めした　たはつ　いちぶ　つうじょう　てさぎょう　きつね　みすえる　いりぐち　かめれおん",
	},
}

func TestBip39KnownEntropy(t *testing.T) {
	for tno, test := range KnownEntropyTests {
		if len(test) != 3 {
			panic("bad test-vector")
		}
		lang, entropyHex, mnemonic := test[0], test[1], test[2]
		entropy, err := hex.DecodeString(entropyHex)
		if err != nil {
			panic(err)
		}
		if bip39.WordLists[lang] == nil {
			panic("bad lang" + lang)
		}
		resMnemonic, err := bip39.MnemonicFromEntropy(entropy, bip39.WordLists[lang])
		if err != nil {
			t.Errorf("SeedFromMnemonic: %v", err)
			continue
		}
		if strings.Join(resMnemonic, bip39.LangSpace[lang]) != mnemonic {
			t.Errorf("test %v:%v: incorrect mnemonic: '%v' vs '%v'", lang, tno, resMnemonic, mnemonic)
		}
	}
}

const NumIterations = 1

func TestBip39RandomEntropy(t *testing.T) {
	for i := 0; i < NumIterations; i++ {
		// Tests with local entropy (random)
		entropyTest(t, 128, "english")
		entropyTest(t, 160, "english")
		entropyTest(t, 192, "english")
		entropyTest(t, 224, "english")
		entropyTest(t, 256, "english")

		entropyTest(t, 128, "japanese")
		entropyTest(t, 160, "japanese")
		entropyTest(t, 192, "japanese")
		entropyTest(t, 224, "japanese")
		entropyTest(t, 256, "japanese")

		entropyTest(t, 128, "chinese_simplified")
		entropyTest(t, 160, "chinese_simplified")
		entropyTest(t, 192, "chinese_simplified")
		entropyTest(t, 224, "chinese_simplified")
		entropyTest(t, 256, "chinese_simplified")

		entropyTest(t, 128, "chinese_traditional")
		entropyTest(t, 160, "chinese_traditional")
		entropyTest(t, 192, "chinese_traditional")
		entropyTest(t, 224, "chinese_traditional")
		entropyTest(t, 256, "chinese_traditional")

		entropyTest(t, 128, "czech")
		entropyTest(t, 160, "czech")
		entropyTest(t, 192, "czech")
		entropyTest(t, 224, "czech")
		entropyTest(t, 256, "czech")

		entropyTest(t, 128, "french")
		entropyTest(t, 160, "french")
		entropyTest(t, 192, "french")
		entropyTest(t, 224, "french")
		entropyTest(t, 256, "french")

		entropyTest(t, 128, "italian")
		entropyTest(t, 160, "italian")
		entropyTest(t, 192, "italian")
		entropyTest(t, 224, "italian")
		entropyTest(t, 256, "italian")

		entropyTest(t, 128, "korean")
		entropyTest(t, 160, "korean")
		entropyTest(t, 192, "korean")
		entropyTest(t, 224, "korean")
		entropyTest(t, 256, "korean")

		entropyTest(t, 128, "portuguese")
		entropyTest(t, 160, "portuguese")
		entropyTest(t, 192, "portuguese")
		entropyTest(t, 224, "portuguese")
		entropyTest(t, 256, "portuguese")

		entropyTest(t, 128, "spanish")
		entropyTest(t, 160, "spanish")
		entropyTest(t, 192, "spanish")
		entropyTest(t, 224, "spanish")
		entropyTest(t, 256, "spanish")
	}
}

func entropyTest(t *testing.T, size int, lang string) {
	entropy := make([]byte, size/8)
	_, err := rand.Read(entropy)
	if err != nil {
		panic(err)
	}
	_, err = bip39.MnemonicFromEntropy(entropy, bip39.EnglishWordList)
	if err != nil {
		t.Errorf("MnemonicFromEntropy: %v (with %v entropy %v lang)", err, size, lang)
	}
}
