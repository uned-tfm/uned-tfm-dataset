import axios from "axios";
import {
  Db,
  MongoClient,
  ObjectId,
  OptionalUnlessRequiredId,
  ServerApiVersion,
} from "mongodb";
import { readFileSync } from "fs";

type HttpResponse<T> = {
  data: T;
  status: number;
  statusText: string;
};

type MalwareApiResponse = {
  query_status: string;
  data: Array<MalwareData>;
};

type MalwareData = {
  sha3_384_hash: string;
  first_seen: string;
  md5_hash: string;
  last_seen: null;
  signature: string;
  file_information: { context: string; value: string }[];
  ssdeep: string;
  telfhash?: unknown;
  sha256_hash: string;
  imphash: string;
  file_type: string;
  delivery_method: string;
  code_sign?: unknown;
  archive_pw?: unknown;
  comments?: unknown;
  file_name: string;
  reporter: string;
  file_type_mime: string;
  file_size: number;
  origin_country: string;
  tags: string[];
  intelligence: {
    mail: null;
    clamav: string[];
    downloads: string;
    uploads: string;
  };
  yara_rules: unknown[];
  gimphash?: unknown;
  sha1_hash: string;
  vendor_intel: unknown;
  anonymous: number;
  dhash_icon: string;
  comment?: unknown;
  tlsh: string;
  ole_information: unknown[];
};

class MalwareScrapper {
  private readonly WRITTEN_BATCH_MAX_SIZE = 50;

  private BATCH_MALWARE_RESULTS: MalwareData[] = [];
  private WRITTEN_BATCHES_COUNTER = 0;

  constructor(private readonly mongoService: MongoService) {}

  async processMalwareResult(
    result: MalwareApiResponse,
    force = false
  ): Promise<void> {
    const OK_RESULT = "ok";
    const { query_status, data } = result;

    if (query_status !== OK_RESULT) {
      return;
    }

    if (
      this.BATCH_MALWARE_RESULTS.length >= this.WRITTEN_BATCH_MAX_SIZE ||
      force === true
    ) {
      await this.mongoService.insertMany(this.BATCH_MALWARE_RESULTS);

      console.log(
        `Written ${
          this.WRITTEN_BATCH_MAX_SIZE * this.WRITTEN_BATCHES_COUNTER +
          this.BATCH_MALWARE_RESULTS.length
        }`
      );

      this.BATCH_MALWARE_RESULTS = [];
      this.WRITTEN_BATCHES_COUNTER++;
    } else {
      const malware = { ...data[0], _id: new ObjectId() };
      this.BATCH_MALWARE_RESULTS = this.BATCH_MALWARE_RESULTS.concat(malware);
    }
  }
}

class MalwareHttpService {
  private readonly API_URL = "https://mb-api.abuse.ch/api/v1/";
  private readonly API_KEY = "0f9662bf152c772cf3a693146c3bfd7d";

  async post(md5: string): Promise<HttpResponse<MalwareApiResponse>> {
    const body = {
      query: "get_info",
      hash: md5,
    };
    return axios.postForm<MalwareApiResponse>(this.API_URL, body, {
      headers: { "API-KEY": this.API_KEY },
    });
  }
}

class MongoService {
  private readonly URI = "mongodb://root:qwjkl5,4@localhost:27017";
  private readonly BD_NAME = "tfm";
  private readonly COLLECTION_NAME = "malware_data";

  private DB_CONN: Db;

  async startConnection(): Promise<void> {
    const client = new MongoClient(this.URI, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    });

    await client.connect();
    this.DB_CONN = client.db(this.BD_NAME);

    console.log("You successfully connected to MongoDB!");
  }

  async insertMany<T>(docs: OptionalUnlessRequiredId<T>[]): Promise<void> {
    console.log(`<-- WRITING DATA -->`);
    const db_collection = this.DB_CONN.collection<T>(this.COLLECTION_NAME);
    await db_collection.insertMany(docs);
  }
}

main();

async function main(): Promise<void> {
  const mongoService = new MongoService();
  await mongoService.startConnection();

  const malwareApiService = new MalwareHttpService();
  const malwareScrapper = new MalwareScrapper(mongoService);

  // Del final hacia adelante
  const md5_ids = readMd5File(50, true);

  // Del principio al final
  // const md5_ids = readMd5File(50, false);

  try {
    let counter = 1;
    const total = md5_ids.length;
    console.log(
      `========================== START PROCESS ========================== `
    );

    for (const md5 of md5_ids) {
      console.log(
        `<-- Md5 ${counter} of ${total} [${(counter * 100) / total}%] -->`
      );

      let result;
      try {
        result = await malwareApiService.post(md5);

        console.log(`<-- API REQUEST RESPONSE CODE ${result.status} -->`);

        if (result.status != 200) {
          console.log(`<---- ERROR IN Md5 ${counter} ---->`);
          await malwareScrapper.processMalwareResult(result.data, true);
          console.log(
            `========================== END PROCESS ========================== `
          );
          return;
        }

        if (counter === total) {
          await malwareScrapper.processMalwareResult(result.data, true);
        } else {
          await malwareScrapper.processMalwareResult(result.data);
        }

        console.log(`<- Waiting 0.1 seconds to continue ->`);
        await delay(100);
      } catch (err) {
        console.log(`<---- ERROR IN HTTP SERVICE ---->`);
        console.log(`<- Waiting 30 second to continue ->`);
        await delay(3000);
      }

      counter++;
    }

    console.log(
      `========================== END PROCESS ========================== `
    );
  } catch (e) {
    console.log(e);
  }
}

function readMd5File(limit = 100, inverse = false): string[] {
  const md5File = readFileSync(__dirname + "/full_md5.txt", "utf-8").split(
    /\r?\n/
  );
  let dataset = md5File.filter(
    (line) => !line.includes("#") && line.length > 0
  );

  if (inverse) {
    dataset = dataset.reverse();
  }

  if (limit !== 100) {
    const max = (dataset.length * limit) / 100;
    dataset = dataset.slice(0, max);
  }

  return dataset;
}

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
