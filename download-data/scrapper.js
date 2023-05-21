const axios = require('axios');
const fs = require('fs');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const API_KEY = '0f9662bf152c772cf3a693146c3bfd7d';
const WRITTEN_BATCH_MAX_SIZE = 5;

let MD5_IDS = [];
let batchMalwareResults = [];
let writtenBatches = 0;

let myDb;

async function get(hash) {
  const body = {
    query: 'get_info',
    hash
  };
  return axios.post('https://mb-api.abuse.ch/api/v1/', body, { headers: { 'API-KEY': API_KEY } });
}

function readMd5File() {
  let md5File = fs.readFileSync('full_md5.txt', 'utf-8');
  md5File = md5File.split(/\r?\n/);
  MD5_IDS = md5File.filter((line) => !line.includes('#') && line.length > 0);
}

const test = {
  query_status: 'ok',
  data: [
    {
      sha256_hash: '878f78260ff0cc10af5b6aef90f7352b83dd20db8394db7ba06bb3230a54e674',
      sha3_384_hash:
        '124ee1b06954b23838ab46726daed22ac96ee0753efa3c7a17bfb0a285b321bdaf649fb6b8ff3aedbb2705e801e56141',
      sha1_hash: '024b552ac2febd5cca46fa170c594f5aaa041f13',
      md5_hash: 'abe5e9cbd99c3bab730ef9a096891bd4',
      first_seen: '2023-04-28 05:00:10',
      last_seen: null,
      file_name: 'DHL SHIPPING DOCUMENT.exe',
      file_size: 611840,
      file_type_mime: 'application/x-dosexec',
      file_type: 'exe',
      reporter: 'abuse_ch',
      origin_country: 'NL',
      anonymous: 0,
      signature: 'Loki',
      imphash: 'f34d5f2d4577ed6d9ceec516c1f5a744',
      tlsh: 'T112D47B52A024C81FFE55DB70C1B4FFE4A6F0FD73A4E5542223793989EAB9B021E8D158',
      telfhash: null,
      gimphash: null,
      ssdeep:
        '12288:uOsnxnueUElJ/vxsXxs2egQVtp3GnmAj+lKQeJPt6en4wPMtAsq3AVxs:yn3UElfshsumTxgPtWxEOs',
      dhash_icon: '8e173733330f693b',
      comment: null,
      archive_pw: null,
      tags: ['DHL', 'exe', 'Loki'],
      code_sign: null,
      delivery_method: 'email_attachment',
      intelligence: {
        clamav: ['Sanesecurity.Malware.28872.BadIN4.UNOFFICIAL'],
        downloads: '238',
        uploads: '1',
        mail: null
      },
      file_information: [
        {
          context: 'cape',
          value: 'https://www.capesandbox.com/analysis/385327/'
        }
      ],
      ole_information: [],
      yara_rules: [
        {
          rule_name: 'pe_imphash',
          author: null,
          description: null,
          reference: null
        },
        {
          rule_name: 'Skystars_Malware_Imphash',
          author: 'Skystars LightDefender',
          description: 'imphash',
          reference: null
        }
      ],
      vendor_intel: {
        'ANY.RUN': [
          {
            malware_family: 'lokibot',
            verdict: 'Malicious activity',
            file_name: 'DHL SHIPPING DOCUMENT.exe',
            date: '2023-04-28 05:02:30',
            analysis_url: 'https://app.any.run/tasks/60aa3b83-2a2a-4cd5-8958-21f5c3298dd9',
            tags: ['trojan', 'lokibot']
          }
        ],
        'CERT-PL_MWDB': {
          detection: null,
          link: 'https://mwdb.cert.pl/sample/878f78260ff0cc10af5b6aef90f7352b83dd20db8394db7ba06bb3230a54e674/'
        },
        YOROI_YOMI: {
          detection: 'Lokibot',
          score: '0.90'
        },
        vxCube: {
          verdict: 'malware1',
          maliciousness: '88',
          behaviour: [
            {
              threat_level: 'suspicious',
              rule: 'Moving of the original file'
            },
            {
              threat_level: 'neutral',
              rule: 'Searching for the window'
            },
            {
              threat_level: 'neutral',
              rule: 'Creating a window'
            },
            {
              threat_level: 'neutral',
              rule: "Enabling the 'hidden' option for analyzed file"
            }
          ]
        },
        Intezer: {
          verdict: 'malicious',
          family_name: 'Loki',
          analysis_url:
            'https://analyze.intezer.com/analyses/804484bc-d336-449a-a355-6917f14fa233?utm_source=MalwareBazaar'
        },
        InQuest: {
          verdict: 'UNKNOWN',
          url: null,
          details: [
            {
              category: 'info',
              title: 'Windows PE Executable',
              description:
                'Found a Windows Portable Executable (PE) binary. Depending on context, the presence of a binary is suspicious or malicious.'
            }
          ]
        },
        CAPE: {
          detection: 'LokiBot',
          link: 'https://www.capesandbox.com/analysis/385327/'
        },
        Triage: {
          malware_family: 'lokibot',
          score: '10',
          link: 'https://tria.ge/reports/230428-fnjnrsbh97/',
          tags: ['family:lokibot', 'collection', 'spyware', 'stealer', 'trojan'],
          signatures: [
            {
              signature: 'Lokibot',
              score: '10'
            },
            {
              signature: 'Reads user/profile data of web browsers',
              score: '7'
            },
            {
              signature: 'Accesses Microsoft Outlook profiles',
              score: '6'
            },
            {
              signature: 'Suspicious use of SetThreadContext',
              score: '5'
            },
            {
              signature: 'Suspicious behavior: EnumeratesProcesses',
              score: null
            },
            {
              signature: 'Suspicious behavior: RenamesItself',
              score: null
            },
            {
              signature: 'Suspicious use of AdjustPrivilegeToken',
              score: null
            },
            {
              signature: 'Suspicious use of WriteProcessMemory',
              score: null
            },
            {
              signature: 'outlook_office_path',
              score: null
            },
            {
              signature: 'outlook_win_path',
              score: null
            }
          ],
          malware_config: [
            {
              extraction: 'c2',
              family: 'lokibot',
              c2: 'http://104.156.227.195/~blog/?p=6151643'
            },
            {
              extraction: 'c2',
              family: 'lokibot',
              c2: 'http://kbfvzoboss.bid/alien/fre.php'
            },
            {
              extraction: 'c2',
              family: 'lokibot',
              c2: 'http://alphastand.trade/alien/fre.php'
            },
            {
              extraction: 'c2',
              family: 'lokibot',
              c2: 'http://alphastand.win/alien/fre.php'
            },
            {
              extraction: 'c2',
              family: 'lokibot',
              c2: 'http://alphastand.top/alien/fre.php'
            }
          ]
        },
        ReversingLabs: {
          threat_name: 'ByteCode-MSIL.Trojan.LokiBot',
          status: 'MALICIOUS',
          first_seen: '2023-04-28 05:01:08',
          scanner_count: '24',
          scanner_match: '17',
          scanner_percent: '70.83'
        },
        Spamhaus_HBL: [
          {
            detection: 'malicious',
            link: 'https://www.spamhaus.org/hbl/'
          }
        ],
        UnpacMe: [
          {
            sha256_hash: '53d1dab429165f086f39aec3149a220d8f615c4d034beafc76aefebfde264073',
            md5_hash: '6639b91edef787d38e118d96ef33f631',
            sha1_hash: 'fd71ceebb618ef9a9635771b764f946de3fd45fb',
            detections: [],
            link: 'https://www.unpac.me/results/87ed31d8-1e76-4958-b620-81d21d5df11f/'
          },
          {
            sha256_hash: '538af2549d4e80d1e7d08a336d46bf713d200c142b7ede293d6dee4a49050a59',
            md5_hash: 'bc8ce7018083c5fb3cd1cdf0309b50f4',
            sha1_hash: 'e110ec1e71a34478b23760a22466f71a1d9cb4fa',
            detections: ['lokibot', 'win_lokipws_auto', 'win_lokipws_g0'],
            link: 'https://www.unpac.me/results/87ed31d8-1e76-4958-b620-81d21d5df11f/'
          },
          {
            sha256_hash: '7b2594d1dde40f9f6aac2762eb7f5f4c480b5b3dff70ff8b87fda6318c52ce16',
            md5_hash: '84e4657b1dc3e0f66e4c18a327099428',
            sha1_hash: 'dbc9c0619b515fb06ccb7d43cc9ca913a8523da9',
            detections: [],
            link: 'https://www.unpac.me/results/87ed31d8-1e76-4958-b620-81d21d5df11f/'
          },
          {
            sha256_hash: 'af0925e4c632166ff87032bc43ea4f85a3805db3782a49724d125f44c0731114',
            md5_hash: 'b9897ba5e468e516e162fd3790a9ddbc',
            sha1_hash: 'db264c796e4a36a45af11e8a7bf71cf0dadce0f0',
            detections: [],
            link: 'https://www.unpac.me/results/87ed31d8-1e76-4958-b620-81d21d5df11f/'
          },
          {
            sha256_hash: 'e5518e76f14e87bcc58a705c6f8f3a686cbffefc0e55985d17a067adfddf3688',
            md5_hash: '920a2854e9c183ad2ef7d5543c296d38',
            sha1_hash: '2c20da753bdf6f1a46261e2c132dd42f75c94229',
            detections: [],
            link: 'https://www.unpac.me/results/87ed31d8-1e76-4958-b620-81d21d5df11f/'
          },
          {
            sha256_hash: '878f78260ff0cc10af5b6aef90f7352b83dd20db8394db7ba06bb3230a54e674',
            md5_hash: 'abe5e9cbd99c3bab730ef9a096891bd4',
            sha1_hash: '024b552ac2febd5cca46fa170c594f5aaa041f13',
            detections: [],
            link: 'https://www.unpac.me/results/87ed31d8-1e76-4958-b620-81d21d5df11f/'
          }
        ],
        VMRay: {
          verdict: 'malicious',
          malware_family: 'Lokibot',
          report_link: 'https://www.vmray.com/analyses/_mb/878f78260ff0/report/overview.html'
        },
        'FileScan-IO': {
          verdict: 'MALICIOUS',
          threatlevel: '1',
          confidence: '1',
          report_link:
            'https://www.filescan.io/uploads/644b530fa020199dc6479d6b/reports/97bece95-50b9-4537-935a-25887e6de218/overview'
        }
      },
      comments: null
    }
  ]
};

async function processApiResult(result) {
  const OK_RESULT = 'ok';
  const { query_status, data } = result;

  if (query_status !== OK_RESULT) {
    return;
  }

  if (batchMalwareResults.length >= WRITTEN_BATCH_MAX_SIZE) {
    await addDocumentsToMongo(batchMalwareResults);

    batchMalwareResults = [];
    writtenBatches++;
    console.log(`Written ${WRITTEN_BATCH_MAX_SIZE * writtenBatches}`);
  } else {
    const malware = { ...data[0], _id: new ObjectId() };
    batchMalwareResults = batchMalwareResults.concat(malware);
  }
}

async function connectToMongo() {
  const uri = 'mongodb://root:qwjkl5,4@localhost:27017';

  const client = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true
    }
  });

  await client.connect();
  myDb = await client.db('tfm');

  console.log('You successfully connected to MongoDB!');
}

async function addDocumentsToMongo(docs) {
  const collection = myDb.collection('malware');
  await collection.insertMany(docs);
}

async function main() {
  await connectToMongo();

  readMd5File();

  for (const id of MD5_IDS) {
  }

  while (writtenBatches < 10) {
    await processApiResult(test);
  }
}

main();
