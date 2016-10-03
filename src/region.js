import AWS from 'aws-sdk';
import request from 'superagent';

const identityUrl = 'http://169.254.169.254/latest/dynamic/instance-identity/document';

let regionPromise = null;

async function reallyGetRegion() {
  const response = await request
    .get(identityUrl)
    .set('Accept', 'application/json');
  regionPromise = null;
  AWS.config.update({
    region: response.body.region,
  });
}

export default function getRegion() {
  // KMS shortstop handler needs a region. See if the env has it
  if (process.env.AWS_REGION) {
    AWS.config.update({
      region: process.env.AWS_REGION,
    });
    return null;
  }
  if (regionPromise) {
    return regionPromise;
  }
  regionPromise = reallyGetRegion();
  return regionPromise;
}
