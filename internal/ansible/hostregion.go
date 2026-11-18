// ansbui — a single-binary web UI for an Ansible control node.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package ansible

import "strings"

// RegionFromHostname returns a "<Subdivision>, <CC>" label if the
// leftmost DNS label of name starts with a known `<cc>-<ss>` prefix,
// or "" if not. Comparison is case-insensitive. Used to populate
// Host.Region from operator-controlled hostnames before the
// optional ipinfo.io enrichment runs — operator labels are usually
// more authoritative than IP geoip, and the existing
// "skip if h.Region != """ in enrichInventory naturally lets geoip
// fill in only the hosts whose hostnames don't match.
//
// The table covers the country/subdivision codes the operator's
// fleet actually uses (US, CA, DE, NL, IN, FI, GB) — extending to a
// new country is just a block of map entries, no logic change.
func RegionFromHostname(name string) string {
	if name == "" {
		return ""
	}
	if dot := strings.IndexByte(name, '.'); dot != -1 {
		name = name[:dot]
	}
	parts := strings.SplitN(strings.ToLower(name), "-", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return hostRegionLabels[parts[0]+"-"+parts[1]]
}

// hostRegionLabels maps "<cc>-<ss>" (lowercase) to a human-readable
// "<Subdivision Name>, <CC>" label. Country code is uppercase in the
// rendered label to match the format that ipinfo.io returns
// ("San Francisco, US"), so the two sources blend cleanly in the UI.
var hostRegionLabels = map[string]string{
	// United States — 50 states + DC, USPS codes.
	"us-al": "Alabama, US",
	"us-ak": "Alaska, US",
	"us-az": "Arizona, US",
	"us-ar": "Arkansas, US",
	"us-ca": "California, US",
	"us-co": "Colorado, US",
	"us-ct": "Connecticut, US",
	"us-de": "Delaware, US",
	"us-dc": "District of Columbia, US",
	"us-fl": "Florida, US",
	"us-ga": "Georgia, US",
	"us-hi": "Hawaii, US",
	"us-id": "Idaho, US",
	"us-il": "Illinois, US",
	"us-in": "Indiana, US",
	"us-ia": "Iowa, US",
	"us-ks": "Kansas, US",
	"us-ky": "Kentucky, US",
	"us-la": "Louisiana, US",
	"us-me": "Maine, US",
	"us-md": "Maryland, US",
	"us-ma": "Massachusetts, US",
	"us-mi": "Michigan, US",
	"us-mn": "Minnesota, US",
	"us-ms": "Mississippi, US",
	"us-mo": "Missouri, US",
	"us-mt": "Montana, US",
	"us-ne": "Nebraska, US",
	"us-nv": "Nevada, US",
	"us-nh": "New Hampshire, US",
	"us-nj": "New Jersey, US",
	"us-nm": "New Mexico, US",
	"us-ny": "New York, US",
	"us-nc": "North Carolina, US",
	"us-nd": "North Dakota, US",
	"us-oh": "Ohio, US",
	"us-ok": "Oklahoma, US",
	"us-or": "Oregon, US",
	"us-pa": "Pennsylvania, US",
	"us-ri": "Rhode Island, US",
	"us-sc": "South Carolina, US",
	"us-sd": "South Dakota, US",
	"us-tn": "Tennessee, US",
	"us-tx": "Texas, US",
	"us-ut": "Utah, US",
	"us-vt": "Vermont, US",
	"us-va": "Virginia, US",
	"us-wa": "Washington, US",
	"us-wv": "West Virginia, US",
	"us-wi": "Wisconsin, US",
	"us-wy": "Wyoming, US",

	// Canada — 10 provinces + 3 territories, ISO 3166-2:CA.
	"ca-ab": "Alberta, CA",
	"ca-bc": "British Columbia, CA",
	"ca-mb": "Manitoba, CA",
	"ca-nb": "New Brunswick, CA",
	"ca-nl": "Newfoundland and Labrador, CA",
	"ca-ns": "Nova Scotia, CA",
	"ca-nt": "Northwest Territories, CA",
	"ca-nu": "Nunavut, CA",
	"ca-on": "Ontario, CA",
	"ca-pe": "Prince Edward Island, CA",
	"ca-qc": "Québec, CA",
	"ca-sk": "Saskatchewan, CA",
	"ca-yt": "Yukon, CA",

	// Germany — 16 Länder, ISO 3166-2:DE.
	"de-bw": "Baden-Württemberg, DE",
	"de-by": "Bavaria, DE",
	"de-be": "Berlin, DE",
	"de-bb": "Brandenburg, DE",
	"de-hb": "Bremen, DE",
	"de-hh": "Hamburg, DE",
	"de-he": "Hesse, DE",
	"de-mv": "Mecklenburg-Vorpommern, DE",
	"de-ni": "Lower Saxony, DE",
	"de-nw": "North Rhine-Westphalia, DE",
	"de-rp": "Rhineland-Palatinate, DE",
	"de-sl": "Saarland, DE",
	"de-sn": "Saxony, DE",
	"de-st": "Saxony-Anhalt, DE",
	"de-sh": "Schleswig-Holstein, DE",
	"de-th": "Thuringia, DE",

	// Netherlands — 12 provinces, ISO 3166-2:NL.
	"nl-dr": "Drenthe, NL",
	"nl-fl": "Flevoland, NL",
	"nl-fr": "Friesland, NL",
	"nl-ge": "Gelderland, NL",
	"nl-gr": "Groningen, NL",
	"nl-li": "Limburg, NL",
	"nl-nb": "North Brabant, NL",
	"nl-nh": "North Holland, NL",
	"nl-ov": "Overijssel, NL",
	"nl-ut": "Utrecht, NL",
	"nl-ze": "Zeeland, NL",
	"nl-zh": "South Holland, NL",

	// India — 28 states + 8 union territories, ISO 3166-2:IN.
	"in-an": "Andaman and Nicobar Islands, IN",
	"in-ap": "Andhra Pradesh, IN",
	"in-ar": "Arunachal Pradesh, IN",
	"in-as": "Assam, IN",
	"in-br": "Bihar, IN",
	"in-ch": "Chandigarh, IN",
	"in-ct": "Chhattisgarh, IN",
	"in-dn": "Dadra and Nagar Haveli and Daman and Diu, IN",
	"in-dl": "Delhi, IN",
	"in-ga": "Goa, IN",
	"in-gj": "Gujarat, IN",
	"in-hr": "Haryana, IN",
	"in-hp": "Himachal Pradesh, IN",
	"in-jk": "Jammu and Kashmir, IN",
	"in-jh": "Jharkhand, IN",
	"in-ka": "Karnataka, IN",
	"in-kl": "Kerala, IN",
	"in-la": "Ladakh, IN",
	"in-ld": "Lakshadweep, IN",
	"in-mp": "Madhya Pradesh, IN",
	"in-mh": "Maharashtra, IN",
	"in-mn": "Manipur, IN",
	"in-ml": "Meghalaya, IN",
	"in-mz": "Mizoram, IN",
	"in-nl": "Nagaland, IN",
	"in-od": "Odisha, IN",
	"in-py": "Puducherry, IN",
	"in-pb": "Punjab, IN",
	"in-rj": "Rajasthan, IN",
	"in-sk": "Sikkim, IN",
	"in-tn": "Tamil Nadu, IN",
	"in-tg": "Telangana, IN",
	"in-tr": "Tripura, IN",
	"in-up": "Uttar Pradesh, IN",
	"in-ut": "Uttarakhand, IN",
	"in-wb": "West Bengal, IN",

	// Finland — 19 regions; alpha codes match the convention the
	// operator's hosts use, not the numeric ISO 3166-2:FI codes.
	"fi-uu": "Uusimaa, FI",
	"fi-vs": "Southwest Finland, FI",
	"fi-st": "Satakunta, FI",
	"fi-ka": "Kanta-Häme, FI",
	"fi-pi": "Pirkanmaa, FI",
	"fi-ph": "Päijät-Häme, FI",
	"fi-ky": "Kymenlaakso, FI",
	"fi-ek": "South Karelia, FI",
	"fi-es": "South Savo, FI",
	"fi-ps": "North Savo, FI",
	"fi-pk": "North Karelia, FI",
	"fi-ks": "Central Finland, FI",
	"fi-ep": "South Ostrobothnia, FI",
	"fi-pp": "Ostrobothnia, FI",
	"fi-kp": "Central Ostrobothnia, FI",
	"fi-pn": "North Ostrobothnia, FI",
	"fi-kn": "Kainuu, FI",
	"fi-la": "Lapland, FI",
	"fi-ah": "Åland, FI",

	// United Kingdom — countries.
	"gb-en": "England, GB",
	"gb-sc": "Scotland, GB",
	"gb-wa": "Wales, GB",
	"gb-ni": "Northern Ireland, GB",

	// Romania — 41 counties + Bucharest municipality, ISO 3166-2:RO.
	"ro-ab": "Alba, RO",
	"ro-ar": "Arad, RO",
	"ro-ag": "Argeș, RO",
	"ro-bc": "Bacău, RO",
	"ro-bh": "Bihor, RO",
	"ro-bn": "Bistrița-Năsăud, RO",
	"ro-bt": "Botoșani, RO",
	"ro-bv": "Brașov, RO",
	"ro-br": "Brăila, RO",
	"ro-b":  "Bucharest, RO",
	"ro-bz": "Buzău, RO",
	"ro-cl": "Călărași, RO",
	"ro-cs": "Caraș-Severin, RO",
	"ro-cj": "Cluj, RO",
	"ro-ct": "Constanța, RO",
	"ro-cv": "Covasna, RO",
	"ro-db": "Dâmbovița, RO",
	"ro-dj": "Dolj, RO",
	"ro-gl": "Galați, RO",
	"ro-gr": "Giurgiu, RO",
	"ro-gj": "Gorj, RO",
	"ro-hr": "Harghita, RO",
	"ro-hd": "Hunedoara, RO",
	"ro-il": "Ialomița, RO",
	"ro-is": "Iași, RO",
	"ro-if": "Ilfov, RO",
	"ro-mm": "Maramureș, RO",
	"ro-mh": "Mehedinți, RO",
	"ro-ms": "Mureș, RO",
	"ro-nt": "Neamț, RO",
	"ro-ot": "Olt, RO",
	"ro-ph": "Prahova, RO",
	"ro-sj": "Sălaj, RO",
	"ro-sm": "Satu Mare, RO",
	"ro-sb": "Sibiu, RO",
	"ro-sv": "Suceava, RO",
	"ro-tr": "Teleorman, RO",
	"ro-tm": "Timiș, RO",
	"ro-tl": "Tulcea, RO",
	"ro-vs": "Vaslui, RO",
	"ro-vl": "Vâlcea, RO",
	"ro-vn": "Vrancea, RO",
}
