import { logger, type IAgentRuntime, type Project, type ProjectAgent } from '@elizaos/core';
import saidPlugin from './plugin.ts';
import { character } from './character.ts';

const initCharacter = ({ runtime }: { runtime: IAgentRuntime }) => {
  logger.info('Initializing Said Sentinel');
  logger.info({ name: character.name }, 'Agent name:');
};

export const projectAgent: ProjectAgent = {
  character,
  init: async (runtime: IAgentRuntime) => await initCharacter({ runtime }),
  plugins: [saidPlugin],
};

const project: Project = {
  agents: [projectAgent],
};

export { character } from './character.ts';

export default project;
