import * as dotenv from "dotenv";
import { parse } from "node-html-parser";
import makeFetchCookie from "fetch-cookie";
import { promises as fs } from "fs";

dotenv.config();

const AUTHORIZATION_URL = "https://accounts.leverade.com/oauth/authorize";
const LOGIN_URL = "https://accounts.leverade.com/login";
const TOKEN_URL = "https://api.leverade.com/oauth/token";
const API_URL = "https://api.leverade.com";

let clientId: string;
let clientSecret: string;
let userId: string;
let userEmail: string;
let userPassword: string;
let refereesDataFilepath: string;
let refereesPublicDataFilepath: string;

if (process.env.LEVERADE_CLIENT_ID) {
  clientId = process.env.LEVERADE_CLIENT_ID;
} else {
  console.error("Client ID is missing");
  process.exit(1);
}

if (process.env.LEVERADE_CLIENT_SECRET) {
  clientSecret = process.env.LEVERADE_CLIENT_SECRET;
} else {
  console.error("Client secret is missing");
  process.exit(1);
}

if (process.env.LEVERADE_USER_ID) {
  userId = process.env.LEVERADE_USER_ID;
} else {
  console.error("User ID is missing");
  process.exit(1);
}

if (process.env.LEVERADE_USER_EMAIL) {
  userEmail = process.env.LEVERADE_USER_EMAIL;
} else {
  console.error("User email is missing");
  process.exit(1);
}

if (process.env.LEVERADE_USER_PASSWORD) {
  userPassword = process.env.LEVERADE_USER_PASSWORD;
} else {
  console.error("User password is missing");
  process.exit(1);
}

if (process.env.REFEREES_DATA_FILEPATH) {
  refereesDataFilepath = process.env.REFEREES_DATA_FILEPATH;
} else {
  console.error("Referees data filepath is missing");
  process.exit(1);
}

if (process.env.REFEREES_PUBLIC_DATA_FILEPATH) {
  refereesPublicDataFilepath = process.env.REFEREES_PUBLIC_DATA_FILEPATH;
} else {
  console.error("Referees public data filepath is missing");
  process.exit(1);
}

const fetchCookie = makeFetchCookie(fetch);

const run = async () => {
  await logIn();
  const requestToken = await getRequestToken();
  const accessToken = await getAccessToken(requestToken);
  const refereeLicensesResponseContent = await getReferees(accessToken);
  const { refereeLicenses, profiles, refereeCategories } = distributeEntities(refereeLicensesResponseContent);
  const referees = consolidateReferees(refereeLicenses, profiles, refereeCategories);
  await saveRefereesPublicData(referees);
  await saveRefereesData(referees);
  console.log("Done.");
};

const logIn = async (): Promise<void> => {
  console.log("Retrieving login token...");
  const loginPageResponse = await fetchCookie(LOGIN_URL);
  const parsedLoginPageBody = parse(await loginPageResponse.text());
  const loginTokenInput = parsedLoginPageBody.querySelector("[name=_token]");
  if (!loginTokenInput?.attrs?.value) {
    console.error("No login token found");
    process.exit(1);
  }
  const loginToken = loginTokenInput.attrs.value;
  // console.debug({ loginToken });

  console.log("Logging in...");
  await fetchCookie(LOGIN_URL, {
    method: "post",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    credentials: "include",
    body: new URLSearchParams({
      _token: loginToken,
      email: userEmail,
      password: userPassword,
    }),
    redirect: "manual",
  });
  console.log("Successfully logged in.");
};

const getRequestToken = async (): Promise<string> => {
  let requestToken: string | undefined;

  console.log("Retrieving authorization token...");
  const authorizePageResponse = await fetchCookie(
    `${AUTHORIZATION_URL}?` +
      new URLSearchParams({
        client_id: clientId,
        redirect_uri: "https://tchoukball.ch",
        response_type: "code",
        user_id: userId,
      }),
    {
      redirect: "manual",
    },
  );

  // Checking if the response already contains the request token. This can happen if we're already authorized.
  try {
    requestToken = getRequestTokenFromResponse(authorizePageResponse);
  } catch (error) {
    // No request token yet. That's okay we'll get it further down.
  }

  if (requestToken) {
    console.log("Already authorized. Skipping authorizing");
  } else {
    const parsedAuthorizationPageBody = parse(await authorizePageResponse.text());
    const authorizationTokenInput = parsedAuthorizationPageBody.querySelector("[name=_token]");
    if (!authorizationTokenInput?.attrs?.value) {
      console.error("No authorization token found");
      process.exit(1);
    }
    const authorizationToken = authorizationTokenInput.attrs.value;
    // console.debug({ authorizationToken });

    console.log("Authorizing...");
    const authorizingResponse = await fetchCookie(AUTHORIZATION_URL, {
      method: "post",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      credentials: "include",
      body: new URLSearchParams({
        _token: authorizationToken,
        state: "",
        client_id: clientId,
      }),
      redirect: "manual",
    });

    requestToken = getRequestTokenFromResponse(authorizingResponse);
  }
  console.log("Request token retrieved.");

  return requestToken;
};

const getAccessToken = async (requestToken: string) => {
  console.log("Retrieving access token...");
  const tokenResponse = await fetchCookie(TOKEN_URL, {
    method: "post",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    credentials: "include",
    body: new URLSearchParams({
      client_id: clientId,
      redirect_uri: "https://tchoukball.ch",
      client_secret: clientSecret,
      grant_type: "authorization_code",
      code: requestToken,
    }),
  });
  const data = await tokenResponse.json();
  console.log("Access token retrieved.");
  return data.access_token;
};

/**
 * Checks the Location header of a response for a `code` query string, which represents the request token
 */
const getRequestTokenFromResponse = (response: Response): string => {
  const locationHeader = response.headers.get("location");
  if (!locationHeader) {
    throw new Error("No location header");
  }

  // console.debug({ locationHeader });

  const locationUrl = new URL(locationHeader);
  const requestToken = locationUrl.searchParams.get("code");

  // console.debug({ requestToken });

  if (!requestToken) {
    throw new Error("No code in redirect URL");
  }

  return requestToken;
};

const getReferees = async (accessToken: string): Promise<any> => {
  console.log("Retrieving referees...");
  let hasMorePages = true;
  let page = 1;
  const referees: LeveradeRefereeLicensesResponseContent = {
    data: [],
    included: [],
  };
  while (hasMorePages) {
    const response = await getRefereePage(accessToken, page);
    const responseContent: LeveradeRefereeLicensesResponseContent = await response.json();
    if (responseContent.data && responseContent.included) {
      referees.data.push(...responseContent.data);
      referees.included?.push(...responseContent.included);
    }
    hasMorePages = !!responseContent.links?.next;
    page++;
  }
  console.log("Referees retrieved.");

  return referees;
};

const getRefereePage = async (accessToken: string, page: number = 1, amount: number = 100): Promise<Response> => {
  console.log(`Retrieving page ${page}...`);
  return await fetch(
    `${API_URL}/licenses?` +
      new URLSearchParams({
        filter: "type:referee",
        include: "profile,refereecategory",
        "page[number]": page.toString(),
        "page[size]": amount.toString(),
      }),
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.api+json",
      },
    },
  );
};

const distributeEntities = (
  refereeLicensesResponseContent: LeveradeRefereeLicensesResponseContent,
): {
  refereeLicenses: LeveradeRefereeLicense[];
  profiles: { [id: string]: LeveradeProfile };
  refereeCategories: { [id: string]: LeveradeRefereeCategory };
} => {
  console.log("Distributing entities...");
  const profiles: { [id: string]: LeveradeProfile } = {};
  const refereeCategories: { [id: string]: LeveradeRefereeCategory } = {};

  refereeLicensesResponseContent.included?.forEach((entity) => {
    switch (entity.type) {
      case "profile":
        profiles[entity.id] = entity;
        break;
      case "refereecategory":
        refereeCategories[entity.id] = entity;
        break;
    }
  });

  return {
    refereeLicenses: refereeLicensesResponseContent.data,
    profiles,
    refereeCategories,
  };
};

const consolidateReferees = (
  refereeLicenses: LeveradeRefereeLicense[],
  profiles: { [id: string]: LeveradeProfile },
  refereeCategories: { [id: string]: LeveradeRefereeCategory },
): Referee[] => {
  console.log("Consolidating referees...");
  const consolidatedReferees = refereeLicenses.map((refereeLicense) => {
    const profile = profiles[refereeLicense.relationships.profile.data.id];
    if (!profile) {
      console.error(`Referee license with ID ${refereeLicense.id} has no profile attached to it`);
    }

    const category = refereeCategories[refereeLicense.relationships.refereecategory.data.id];
    if (!category) {
      console.error(`Referee license with ID ${refereeLicense.id} has no referee category attached to it`);
    }

    return {
      id: refereeLicense.id,
      inactive: !!refereeLicense.attributes.custom_fields.inactive,
      firstName: profile.attributes.first_name,
      lastName: profile.attributes.last_name,
      email: profile.attributes.email,
      phone: profile.attributes.phone,
      residence: profile.attributes.residence,
      levelId: category.id as RefereeLevel,
    };
  });

  console.log("Sort referees...");
  return consolidatedReferees.sort((refereeA, refereeB) => {
    let compareValue = refereeA.levelId.localeCompare(refereeB.levelId);

    if (!compareValue) {
      compareValue = refereeA.lastName.localeCompare(refereeB.lastName);
    }

    if (!compareValue) {
      compareValue = refereeA.firstName.localeCompare(refereeB.lastName);
    }

    return compareValue;
  });
};

const saveRefereesPublicData = async (referees: Referee[]): Promise<void> => {
  console.log("Saving referees public data...");
  const refereesPublicData = referees
    .filter((referee) => !referee.inactive)
    .map((referee) => ({
      id: referee.id,
      firstName: referee.firstName,
      lastName: referee.lastName,
      levelId: referee.levelId,
    }));
  await fs.writeFile(refereesPublicDataFilepath, JSON.stringify(refereesPublicData));
};

const saveRefereesData = async (referees: Referee[]): Promise<void> => {
  console.log("Saving referees full data...");
  const header = ["ID", "Prénom", "Nom", "E-mail", "Téléphone", "Localité", "Niveau"];
  const csv: string = [
    header.join(","), // header row first
    ...referees
      .filter((referee) => !referee.inactive)
      .map((referee) => {
        return [
          referee.id,
          referee.firstName,
          referee.lastName,
          referee.email,
          referee.phone,
          referee.residence ? `"${referee.residence}"` : null,
          getRefereeLevelRomanNumeral(referee.levelId),
        ].join(",");
      }),
  ].join("\r\n");
  await fs.writeFile(refereesDataFilepath, csv);
};

const getRefereeLevelRomanNumeral = (levelId: RefereeLevel): string => {
  switch (levelId) {
    case RefereeLevel.I:
      return "I";
    case RefereeLevel.II:
      return "II";
    case RefereeLevel.III:
      return "III";
    case RefereeLevel.IV:
      return "IV";
    default:
      return "N/A";
  }
};

interface LeveradeResponseContent<T, E = {}> {
  data: T[];
  included?: E[];
  meta?: {
    pagination?: {
      count: number;
      per_page: number;
      current_page: number;
    };
  };
  links?: {
    self: string;
    first: string;
    next?: string;
  };
}

type LeveradeRefereeLicensesResponseContent = LeveradeResponseContent<
  LeveradeRefereeLicense,
  LeveradeProfile | LeveradeRefereeCategory
>;

interface LeveradeBaseEntity {
  type: string;
  id: string;
}

interface LeveradeEntity extends LeveradeBaseEntity {
  attributes: {
    [key: string]: any;
  };
  meta: {
    [key: string]: any;
  };
  relationships: {
    [key: string]: { data: LeveradeBaseEntity | LeveradeBaseEntity[] | null };
  };
}

interface LeveradeRefereeLicense extends LeveradeEntity {
  type: "license";
  attributes: {
    type: "referee";
    custom_fields: {
      inactive: boolean;
    };
  };
  relationships: {
    refereecategory: { data: LeveradeBaseEntity };
    profile: { data: LeveradeBaseEntity };
    [key: string]: { data: LeveradeBaseEntity | LeveradeBaseEntity[] | null };
  };
}

interface LeveradeProfile extends LeveradeEntity {
  type: "profile";
  attributes: {
    first_name: string;
    last_name: string;
    email: string;
    phone: string;
    residence: string;
  };
}

interface LeveradeRefereeCategory extends LeveradeEntity {
  type: "refereecategory";
  attributes: {
    name: string;
  };
}

interface Referee {
  id: string;
  inactive: boolean;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  residence: string;
  levelId: RefereeLevel;
}

enum RefereeLevel {
  I = "305",
  II = "304",
  III = "303",
  IV = "302",
}

run();
