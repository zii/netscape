/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0 (the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of this code under the NPL is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
 */

#include "msg.h"
#include "xp.h"
#include "bytearr.h"

#ifdef XP_WIN16
#define SIZE_T_MAX    0xFF80		            // Maximum allocation size
#define MAX_ARR_ELEMS SIZE_T_MAX/sizeof(BYTE)
#endif


XPByteArray::XPByteArray()
{
	m_nSize = 0;
	m_nMaxSize = 0;
	m_pData = NULL;
}

XPByteArray::~XPByteArray()
{
	SetSize(0);
}

/////////////////////////////////////////////////////////////////////////////

int XPByteArray::GetSize() const
{
	return m_nSize;
}

XP_Bool XPByteArray::SetSize(int nSize)
{
	XP_ASSERT(nSize >= 0);

#ifdef MAX_ARR_ELEMS
	if (nSize > MAX_ARR_ELEMS);
	{
		XP_ASSERT(nSize <= MAX_ARR_ELEMS); // Will fail
		return FALSE;
	}
#endif

	if (nSize == 0)
	{
		// Remove all elements
		XP_FREE(m_pData);
		m_nSize = 0;
		m_nMaxSize = 0;
		m_pData = NULL;
	}
	else if (m_pData == NULL)
	{
		// Create a new array
		m_nMaxSize = MAX(8, nSize);
		m_pData = (BYTE *)XP_CALLOC(1, m_nMaxSize * sizeof(BYTE));
		if (m_pData)
			m_nSize = nSize;
		else
			m_nSize = m_nMaxSize = 0;
	}
	else if (nSize <= m_nMaxSize)
	{
		// The new size is within the current maximum size, make sure new
		// elements are to initialized to zero
		if (nSize > m_nSize)
			XP_MEMSET(&m_pData[m_nSize], 0, (nSize - m_nSize) * sizeof(BYTE));

		m_nSize = nSize;
	}
	else
	{
		// The array needs to grow, figure out how much
		int nGrowBy, nMaxSize;
		nGrowBy  = MIN(1024, MAX(8, m_nSize / 8));
		nMaxSize = MAX(nSize, m_nMaxSize + nGrowBy);
#ifdef MAX_ARR_ELEMS
		nMaxSize = MIN(MAX_ARR_ELEMS, nMaxSize);
#endif

		BYTE *pNewData = (BYTE *)XP_ALLOC(nMaxSize * sizeof(BYTE));
		if (pNewData)
		{
			// Copy the data from the old array to the new one
			XP_MEMCPY(pNewData, m_pData, m_nSize * sizeof(BYTE));

			// Zero out the remaining elements
			XP_MEMSET(&pNewData[m_nSize], 0, (nSize - m_nSize) * sizeof(BYTE));
			m_nSize = nSize;
			m_nMaxSize = nMaxSize;

			// Free the old array
			XP_FREE(m_pData);
			m_pData = pNewData;
		}
	}

	return nSize == m_nSize;
}

/////////////////////////////////////////////////////////////////////////////

BYTE &XPByteArray::ElementAt(int nIndex)
{
	XP_ASSERT(nIndex >= 0 && nIndex < m_nSize);
	return m_pData[nIndex];
}

BYTE XPByteArray::GetAt(int nIndex) const
{
	XP_ASSERT(nIndex >= 0 && nIndex < m_nSize);
	return m_pData[nIndex];
}

void XPByteArray::SetAt(int nIndex, BYTE newElement)
{
	XP_ASSERT(nIndex >= 0 && nIndex < m_nSize);
	m_pData[nIndex] = newElement;
}

/////////////////////////////////////////////////////////////////////////////

int XPByteArray::Add(BYTE newElement)
{
	int nIndex = m_nSize;

#ifdef MAX_ARR_ELEMS
	if (nIndex >= MAX_ARR_ELEMS) 
		return -1;	     
#endif			

	SetAtGrow(nIndex, newElement);
	return nIndex;
}

void XPByteArray::InsertAt(int nIndex, BYTE newElement, int nCount)
{
	XP_ASSERT(nIndex >= 0);
	XP_ASSERT(nCount > 0);

	if (nIndex >= m_nSize)
	{
		// If the new element is after the end of the array, grow the array
		SetSize(nIndex + nCount);
	}
	else
	{
		// The element is being insert inside the array
		int nOldSize = m_nSize;
		SetSize(m_nSize + nCount);

		// Move the data after the insertion point
		XP_MEMMOVE(&m_pData[nIndex + nCount], &m_pData[nIndex],
			       (nOldSize - nIndex) * sizeof(BYTE));
	}

	// Insert the new elements
	XP_ASSERT(nIndex + nCount <= m_nSize);
	while (nCount--)
		m_pData[nIndex++] = newElement;
}

void XPByteArray::InsertAt(int nStartIndex, const XPByteArray *pNewArray)
{
	XP_ASSERT(nStartIndex >= 0);
	XP_ASSERT(pNewArray != NULL);

	if (pNewArray->GetSize() > 0)
	{
		InsertAt(nStartIndex, pNewArray->GetAt(0), pNewArray->GetSize());
		for (int i = 1; i < pNewArray->GetSize(); i++)
			m_pData[nStartIndex + i] = pNewArray->GetAt(i);
	}
}

void XPByteArray::RemoveAll()
{
	SetSize(0);
}

void XPByteArray::RemoveAt(int nIndex, int nCount)
{
	XP_ASSERT(nIndex >= 0);
	XP_ASSERT(nIndex + nCount <= m_nSize);

	if (nCount > 0)
	{
		// Make sure not to overstep the end of the array
		int nMoveCount = m_nSize - (nIndex + nCount);
		if (nCount && nMoveCount >= 0)
			XP_MEMMOVE(&m_pData[nIndex], &m_pData[nIndex + nCount],
		               nMoveCount * sizeof(BYTE));

		m_nSize -= nCount;
	}
}

void XPByteArray::SetAtGrow(int nIndex, BYTE newElement)
{
	XP_ASSERT(nIndex >= 0);

	if (nIndex >= m_nSize)
		SetSize(nIndex+1);
	m_pData[nIndex] = newElement;
}
