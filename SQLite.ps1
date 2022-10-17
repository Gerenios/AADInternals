# Parses SQLite varint V3
# Sep 27th 2022
function Parse-SQLiteVarIntV3
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [ref]$Position
    )
    
    Process
    {
        return Decode-MultiByteInteger -Data $Data -Position $Position -Reverse
    }
}

# Parses SQLite database B-Tree cell payload
# Sep 27th 2022
function Parse-SQLiteBTreeCellPayload
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$false)]
        [int]$MaxColumns=20
    )
    
    Process
    {
        # Ref. https://www.sqlite.org/fileformat.html

        # Parse the header
        $headerSize = $Data[0]

        # Parse the columns        
        $pCol = $headerSize
        $nCol = 0
        $columns = @()
			 
        for($p = 1 ; ($p -lt $headerSize);)
        {
            $serialType = Parse-SQLiteVarIntV3 -Data $Data -Position ([ref]$p)
            switch($serialType)
            {
                # null
                0 {
                    $value = $null
                    break
                }

                # Integer
                1 {
                    $value = [int] $Data[$pCol]; $pCol++
                    break
                }
                
                # Integer
                {$_ -gt 2 -and $_ -lt 8} {
                    switch($_)
                    {
                        {$_ -lt 5} {$nBytes = $_; break}
                        {$_ -eq 5} {$nBytes = 6; break}
                        default    {$nBytes = 8; break}
                        
                    }
                    $bytes = New-Object Byte[] 8
                    [Array]::Copy($Data,$pCol,$bytes,8-$nBytes,$nBytes)
                    [Array]::Reverse($bytes)
                    
                    $value = [bitconverter]::ToInt64($bytes,0); $pCol += $nBytes
                    break
                }
                # Integer 0
                8 {
                    $value = [int64] 0
                    break
                }
                # Integer 1
                9 {
                    $value = [int64] 1
                    break
                }
                # Blob
                {$_ -ge 12 -and $_ % 2 -eq 0}
                {
                    $bLen = ($_ - 12) / 2
                    $value = $Data[$pCol..$($pCol + $bLen -1)]; $pCol += $bLen
                    break
                }
                # String - we'll assume UTF-8 encoding
                {$_ -ge 13 -and $_ % 2 -ne 0}
                {
                    $bLen = ($_ - 13) / 2
                    $value = [System.Text.Encoding]::UTF8.GetString($Data[$pCol..$($pCol + $bLen -1)]); $pCol += $bLen
                    break
                }
            }
            $columns+= $value
        }

        return $columns
    }
}

# Parses SQLite database B-Tree cell
# Sep 27th 2022
function Parse-SQLiteBTreeCell
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [int]$Position,
        [Parameter(Mandatory=$true)]
        [int]$PageType,
        [Parameter(Mandatory=$true)]
        [int]$PageSize
    )
    
    Process
    {
        # Ref. https://www.sqlite.org/fileformat.html

        $p = $Position

        # Overflow calcuation variables
        $u = $PageSize           # We assume no reserverd space
        $m = (($u-12)*32/255)-23 # Always the same

        switch($PageType)
        {
            0x0d #B-Tree Leaf Cell
            {
                $leftChild =         $null
                $payLoadBytes =      Parse-SQLiteVarIntV3 -Data $Data -Position ([ref]$p)
                $rowId =             Parse-SQLiteVarIntV3 -Data $Data -Position ([ref]$p)
                $payLoad =           $Data[$p..$($p + $payloadBytes - 1)] ;$p += $payLoadBytes

                $x = $u-35
                $p = $payLoadBytes
                $k = $m+(($p-$m)%($u-4))

                if($p>$x)
                {
                    # The first K bytes of P are stored on the btree page and the remaining P-K bytes are stored on overflow pages.
                    if($k -le $x) 
                    {
                        $payLoad = $payLoad[0..$k-1]
                        $p -= $payLoadBytes + $k
                    }
                    # The first M bytes of P are stored on the btree page and the remaining P-M bytes are stored on overflow pages
                    else 
                    {
                        $payLoad = $payLoad[0..$m-1]
                        $p -= $payLoadBytes + $m
                    }
                    $firstOverflowPage = [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
                }

                break
            }
            0x05 #B-Tree Interior Cell
            {
                $leftChild =         [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
                $payLoadBytes =      $null
                $rowId =             Parse-SQLiteVarIntV3 -Data $Data -Position ([ref]$p)
                $payLoad =           $null
                $firstOverflowPage = $null
                break
            }
            0x0a #B-Tree Leaf Cell
            {
                $leftChild =         $null
                $payLoadBytes =      Parse-SQLiteVarIntV3 -Data $Data -Position ([ref]$p)
                $rowId =             $null
                $payLoad =           $Data[$p..$($p + $payloadBytes - 1)] ;$p += $payLoadBytes
                
                $x = (($u-12)*64/255)-23
                $p = $payLoadBytes
                $k = $m+(($p-$m)%($u-4))

                if($p>$x)
                {
                    # The first K bytes of P are stored on the btree page and the remaining P-K bytes are stored on overflow pages.
                    if($k -le $x) 
                    {
                        $payLoad = $payLoad[0..$k-1]
                        $p -= $payLoadBytes + $k
                    }
                    # The first M bytes of P are stored on the btree page and the remaining P-M bytes are stored on overflow pages
                    else 
                    {
                        $payLoad = $payLoad[0..$m-1]
                        $p -= $payLoadBytes + $m
                    }
                    $firstOverflowPage = [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
                }

                break
            }
            0x02 #B-Tree Interior Cell
            {
                $leftChild =         [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
                $payLoadBytes =      Parse-SQLiteVarIntV3 -Data $Data -Position ([ref]$p)
                $rowId =             $null
                $payLoad =           $Data[$p..$($p + $payloadBytes - 1)] ;$p += $payLoadBytes
                
                $x = (($u-12)*64/255)-23
                $p = $payLoadBytes
                $k = $m+(($p-$m)%($u-4))

                if($p>$x)
                {
                    # The first K bytes of P are stored on the btree page and the remaining P-K bytes are stored on overflow pages.
                    if($k -le $x) 
                    {
                        $payLoad = $payLoad[0..$k-1]
                        $p -= $payLoadBytes + $k
                    }
                    # The first M bytes of P are stored on the btree page and the remaining P-M bytes are stored on overflow pages
                    else 
                    {
                        $payLoad = $payLoad[0..$m-1]
                        $p -= $payLoadBytes + $m
                    }
                    $firstOverflowPage = [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
                }

                break
            }
        }
        if($payLoad)
        {
            $columns = Parse-SQLiteBTreeCellPayload -Data $payLoad
        }
        $attributes = [ordered]@{
            "LeftChildPageNumber"     = $leftChild
            "PayloadBytes"            = $payLoadBytes
            "Payload"                 = $columns
            "FirstOverFlowPageNumber" = $firstOverflowPage
        }

        return New-Object -TypeName psobject -Property $attributes
    }
}

# Parses SQLite database file
# Sep 27th 2022
function Parse-SQLiteDatabase
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    
    Process
    {
        
        # Parse SQLite db file header 
        $p = 0;
        $header = Parse-SQLiteHeader -Data $Data -Position ([ref]$p)

        # Parse pages
        $pages = New-Object psobject[] $header.Pages
        $nPages = 0
        while($p -lt $Data.Count)
        {
            $pages[$nPages] = Parse-SQLiteBTreePage -Data $Data -Position ([ref]$p) -PageSize $header.PageSize
            $nPages++

            # Next page starts from header size + n*PageSize
            $p = $nPages * $header.PageSize
        }

        $attributes = [ordered]@{
            "Header" = $header
            "Pages" = $pages
        }
        
        return New-Object -TypeName psobject -Property $attributes
    }
}

# Parses SQLite database file B-Tree page
# Sep 27th 2022
function Parse-SQLiteBTreePage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [ref]$Position,
        [Parameter(Mandatory=$true)]
        [int]$PageSize
    )
    
    Process
    {
        # Ref. https://www.sqlite.org/fileformat.html

        $p = $Position.Value

        # Calculate the page start
        if($p -lt $PageSize)
        {
            $pageStart = 0
        }
        else
        {
            $pageStart = $p
        }

        $pageType =           [int]$Data[$p]; $p += 1
        # A value of 2 (0x02) means the page is an interior index b-tree page.
        # A value of 5 (0x05) means the page is an interior table b-tree page.
        # A value of 10 (0x0a) means the page is a leaf index b-tree page.
        # A value of 13 (0x0d) means the page is a leaf table b-tree page.

        $freeBlockStart =               [System.BitConverter]::ToInt16($Data[($p+2-1)..$p],0); $p += 2
        $cellsOnPage =                  [System.BitConverter]::ToInt16($Data[($p+2-1)..$p],0); $p += 2
        $cellContentStart =             [System.BitConverter]::ToInt16($Data[($p+2-1)..$p],0); $p += 2
        if($cellContentStart -eq 0)     # A zero value for this integer is interpreted as 65536.
        {
            $cellContentStart = 65536
        }
        $fragmentedFreeBytes =          [int]$Data[$p]; $p += 1
        if($pageType -eq 0x02)
        {
            $pageNumber =               [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        }
        
        $cells = New-Object psobject[] $cellsOnPage
        for($c = 0 ; $c -lt $cellsOnPage; $c++)
        {
            $cellOffset =             [System.BitConverter]::ToInt16($Data[($p+2-1)..$p],0); $p += 2
            $cellStart = $pageStart + $cellOffset
            $cells[$c] = Parse-SQLiteBTreeCell -Data $Data -Position $cellStart -PageType $pageType -PageSize $PageSize
        }

        $Position.Value = $p

        switch($pageType)
        {
            0x0d {$strPageType = "Table Leaf"    ; break}
            0x05 {$strPageType = "Table Interior"; break}
            0x0a {$strPageType = "Index Leaf"    ; break}
            0x02 {$strPageType = "Index Interior"; break}
        }
        
        $attributes = [ordered]@{
            "PageType"     = $strPageType
            "PageNumber"   = $pageNumber
            "CellsOnPage"  = $cellsOnPage
            "ContentStart" = $cellContentStart
            "Cells"        = $cells
        }

        return New-Object -TypeName psobject -Property $attributes
    }
}

# Parses SQLite database file header
# Sep 27th 2022
function Parse-SQLiteHeader
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [ref]$Position
    )
    
    Begin
    {
        $encodings = @(
            "UTF-8"
            "UTF-16le"
            "UTF-16be"
        )
    }
    Process
    {
        # Ref. https://www.sqlite.org/fileformat.html

        $p = $Position.Value
        
        $headerString =               [text.encoding]::UTF8.GetString($Data[$p..($p+16-1)]); $p += 16
        $dbPageSize =                 [System.BitConverter]::ToInt16($Data[($p+2-1)..$p],0); $p += 2
        if($dbPageSize -eq 1) # The database page size in bytes. Must be a power of two between 512 and 32768 inclusive, or the value 1 representing a page size of 65536.
        {
            $dbPageSize = 65536
        }

        $fileWriteVersion =           [int]$Data[$p]; $p += 1
        $fileReadVersion =            [int]$Data[$p]; $p += 1
        $reservedSpaceBytes =         [int]$Data[$p]; $p += 1

        $maxEmbeddedPayloadFraction = [int]$Data[$p]; $p += 1
        $minEmbeddedPayloadFraction = [int]$Data[$p]; $p += 1
        $leafPayloadFraction =        [int]$Data[$p]; $p += 1

        $fileChangeCounter =          [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        $dbSizePages =                [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        $firstFreelistTrunkPage =     [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        $freelistPages =              [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4

        $schemaCookie =               [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        $schemaFormatNumber =         [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        # A value of 1 means UTF-8. A value of 2 means UTF-16le. A value of 3 means UTF-16be.

        $defaultPageCacheSize =       [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        $largestRootBTreePage =       [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4

        $dbTextEncoding =             [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        $userVersion =                [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        $incrementalVacuumMode =      [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0) -ne 0; $p += 4
        $applicationId =              [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4

        $reserved =                   $Data[$p..($p+20-1)]; $p += 20

        $versionValidForNumber =      [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4
        $versionNumber =              [System.BitConverter]::ToInt32($Data[($p+4-1)..$p],0); $p += 4

        # Check variables
        if($maxEmbeddedPayloadFraction -ne 64)
        {
            Write-Warning "Maximum embedded payload fraction is $maxEmbeddedPayloadFraction, it MUST be 64"
        }

        if($minEmbeddedPayloadFraction -ne 32)
        {
            Write-Warning "Minimum embedded payload fraction is $minEmbeddedPayloadFraction, it MUST be 32"
        }

        if($schemaFormatNumber -ne 4)
        {
            Write-Warning "Schema version $schemaFormatNumber not supported, expected version 4"
        }

        $Position.Value = $p

        $attributes = [ordered]@{
            "PageSize"           = $dbPageSize
            "Pages"              = $dbSizePages
            "Encoding"           = $encodings[$dbTextEncoding-1]
            "ChangeCounter"      = $fileChangeCounter
            "FirstFreelistPage"  = $freelistPages
            "FreelistPages"      = $freelistPages
            "SchemaFormat"       = $schemaFormatNumber
            "SchemaCookie"       = $schemaCookie
            "SQLiteVersion"      = $versionNumber
            "ReservedSpaceBytes" = $reservedSpaceBytes
        }
        
        return New-Object -TypeName PSObject -Property $attributes
    }
}