package main

import (
	"sort"
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
)

type ProfileInfo struct {
	name          string
	clientProfile profiles.ClientProfile
}

func (p *ProfileInfo) Name() string {
	return p.name
}

func (p *ProfileInfo) SupportsHTTP3() bool {
	return len(p.clientProfile.GetHttp3Settings()) > 0 || p.clientProfile.GetHttp3PriorityParam() > 0
}

func (p *ProfileInfo) SupportsPSK() bool {
	return strings.HasSuffix(p.name, "_psk")
}

var profileRegistry = map[string]profiles.ClientProfile{
	"chrome_103":         profiles.Chrome_103,
	"chrome_104":         profiles.Chrome_104,
	"chrome_105":         profiles.Chrome_105,
	"chrome_106":         profiles.Chrome_106,
	"chrome_107":         profiles.Chrome_107,
	"chrome_108":         profiles.Chrome_108,
	"chrome_109":         profiles.Chrome_109,
	"chrome_110":         profiles.Chrome_110,
	"chrome_111":         profiles.Chrome_111,
	"chrome_116_psk":     profiles.Chrome_116_PSK,
	"chrome_116_psk_pq":  profiles.Chrome_116_PSK_PQ,
	"chrome_117":         profiles.Chrome_117,
	"chrome_120":         profiles.Chrome_120,
	"chrome_124":         profiles.Chrome_124,
	"chrome_130_psk":     profiles.Chrome_130_PSK,
	"chrome_131":         profiles.Chrome_131,
	"chrome_131_psk":     profiles.Chrome_131_PSK,
	"chrome_133":         profiles.Chrome_133,
	"chrome_133_psk":     profiles.Chrome_133_PSK,
	"chrome_144":         profiles.Chrome_144,
	"chrome_144_psk":     profiles.Chrome_144_PSK,
	"chrome_146":         profiles.Chrome_146,
	"chrome_146_psk":     profiles.Chrome_146_PSK,
	"safari_15_6_1":      profiles.Safari_15_6_1,
	"safari_16_0":        profiles.Safari_16_0,
	"safari_ipad_15_6":   profiles.Safari_Ipad_15_6,
	"safari_ios_15_5":    profiles.Safari_IOS_15_5,
	"safari_ios_15_6":    profiles.Safari_IOS_15_6,
	"safari_ios_16_0":    profiles.Safari_IOS_16_0,
	"safari_ios_17_0":    profiles.Safari_IOS_17_0,
	"safari_ios_18_0":    profiles.Safari_IOS_18_0,
	"safari_ios_18_5":    profiles.Safari_IOS_18_5,
	"safari_ios_26_0":    profiles.Safari_IOS_26_0,
	"firefox_102":        profiles.Firefox_102,
	"firefox_104":        profiles.Firefox_104,
	"firefox_105":        profiles.Firefox_105,
	"firefox_106":        profiles.Firefox_106,
	"firefox_108":        profiles.Firefox_108,
	"firefox_110":        profiles.Firefox_110,
	"firefox_117":        profiles.Firefox_117,
	"firefox_120":        profiles.Firefox_120,
	"firefox_123":        profiles.Firefox_123,
	"firefox_132":        profiles.Firefox_132,
	"firefox_133":        profiles.Firefox_133,
	"firefox_135":        profiles.Firefox_135,
	"firefox_146_psk":    profiles.Firefox_146_PSK,
	"firefox_147":        profiles.Firefox_147,
	"firefox_147_psk":    profiles.Firefox_147_PSK,
	"opera_89":           profiles.Opera_89,
	"opera_90":           profiles.Opera_90,
	"opera_91":           profiles.Opera_91,
	"zalando_android":    profiles.ZalandoAndroidMobile,
	"zalando_ios":        profiles.ZalandoIosMobile,
	"nike_ios":           profiles.NikeIosMobile,
	"nike_android":       profiles.NikeAndroidMobile,
	"cloudscraper":       profiles.CloudflareCustom,
	"mms_ios":            profiles.MMSIos,
	"mms_ios_2":          profiles.MMSIos2,
	"mms_ios_3":          profiles.MMSIos3,
	"mesh_ios":           profiles.MeshIos,
	"mesh_ios_2":         profiles.MeshIos2,
	"mesh_android":       profiles.MeshAndroid,
	"mesh_android_2":     profiles.MeshAndroid2,
	"confirmed_ios":      profiles.ConfirmedIos,
	"confirmed_android":  profiles.ConfirmedAndroid,
	"okhttp4_android_7":  profiles.Okhttp4Android7,
	"okhttp4_android_8":  profiles.Okhttp4Android8,
	"okhttp4_android_9":  profiles.Okhttp4Android9,
	"okhttp4_android_10": profiles.Okhttp4Android10,
	"okhttp4_android_11": profiles.Okhttp4Android11,
	"okhttp4_android_12": profiles.Okhttp4Android12,
	"okhttp4_android_13": profiles.Okhttp4Android13,
}

func GetProfile(name string) *ProfileInfo {
	if cp, ok := profileRegistry[name]; ok {
		return &ProfileInfo{name: name, clientProfile: cp}
	}
	return nil
}

func ListProfiles() []string {
	names := make([]string, 0, len(profileRegistry))
	for name := range profileRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
