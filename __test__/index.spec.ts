import test from 'ava'

import { buildHeartbeat, getMessageSeq, getMessageType } from '../index'

test('buildHeartbeat + getMessageType/getMessageSeq', (t) => {
  const seq = 123
  const data = buildHeartbeat(seq, 'test-session')
  t.is(getMessageSeq(data), seq)
  t.is(getMessageType(data), 0x2000)
})
